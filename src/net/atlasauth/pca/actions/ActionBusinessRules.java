package net.atlasauth.pca.actions;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Decision;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Predicates;

/**
 * A platform's own business rules for one action (amount ceilings per currency, approval thresholds, caller-scoped records, rate limits,
 * business hours, allowed recipients, required fields) compiled into tighten rules and count accumulators. Every compiled rule carries the
 * signal {@code escalate} or {@code deny}, so a rule can only lower a decision. Everything is a JSON tree (Map / List / String / Boolean /
 * Json.Num / null) so the results compare byte for byte with the reference. A time zone must be an IANA zone id known to the JDK
 * (shortcut: the reference's Intl also accepts a few offset spellings; those are refused here, which fails closed).
 */
public final class ActionBusinessRules {
    private ActionBusinessRules() {}

    public static final List<String> RULE_DAYS = List.of("sun", "mon", "tue", "wed", "thu", "fri", "sat");
    public static final Map<String, Long> RATE_PERIODS = Map.of("hour", 3_600_000L, "day", 86_400_000L);
    public static final int MAX_RULE_CURRENCIES = 32, MAX_RULE_LIST = 64, MAX_RULE_APPROVERS = 16, MAX_RULE_EXAMPLES = 32;
    public static final String BUSINESS_RULES_DOMAIN = "atlas-pca/action-business-rules/v1";
    public static final String RULES_REVIEW_DOMAIN = "atlas-pca/action-rules-review/v1";

    private static final Pattern CCY_RE = Pattern.compile("[A-Z]{3}");
    private static final Pattern NAME_RE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern HHMM_RE = Pattern.compile("([01][0-9]|2[0-3]):([0-5][0-9])");
    private static final Pattern DOMAIN_RE = Pattern.compile("(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+");
    private static final Pattern ADDRESS_RE = Pattern.compile("[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}");
    private static final Pattern DEC_RE = Pattern.compile("(0|[1-9][0-9]{0,14})(?:\\.([0-9]{1,6}))?");
    private static final Pattern AT_RE = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z");
    private static final List<String> RULE_KEYS = List.of("amount", "approval", "scope", "rate", "hours", "recipients", "required", "examples");
    private static final List<String> DAY_NAMES = List.of("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");

    private static boolean isObj(Object v) { return v instanceof Map; }
    private static boolean own(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }
    private static boolean undef(Object o, String k) { return !own(o, k); }
    private static boolean fullMatch(Pattern p, Object v) { return v instanceof String && p.matcher((String) v).matches(); }

    private static void closed(Map<String, Object> o, List<String> allowed, String at) {
        for (String k : o.keySet()) if (!allowed.contains(k)) throw new Actions.ActionKitError("bad_rules", at + ": unknown member '" + k + "'");
    }

    private static RuntimeException bad(String msg) { return new Actions.ActionKitError("bad_rules", msg); }

    private static Map<String, Object> params(Map<String, Object> d) { return J.m(d.get("params")); }

    private static List<String> sortedKeys(Map<String, Object> m) {
        List<String> ks = new ArrayList<>(m.keySet());
        ks.sort(null);
        return ks;
    }

    // ---- references and money ------------------------------------------------------------------------------------------------

    /** The parameter a reference names: {@code {name, p}}. Throws {@code bad_rules} when it resolves to none or to several. */
    public static Map<String, Object> resolveParamRef(Map<String, Object> d, Object r, String at) {
        if (!isObj(r)) throw bad(at + ": name a parameter ({param} or {role})");
        Map<String, Object> rm = J.m(r);
        boolean hasP = rm.get("param") instanceof String, hasR = rm.get("role") instanceof String;
        if (hasP == hasR) throw bad(at + ": give exactly one of param or role");
        Map<String, Object> ps = params(d);
        if (hasP) {
            String name = (String) rm.get("param");
            if (!own(ps, name) || ps.get(name) == null) throw bad(at + ": '" + d.get("verb") + "' has no parameter '" + name + "'");
            return J.obj("name", name, "p", ps.get(name));
        }
        List<String> hits = new ArrayList<>();
        for (String n : ps.keySet()) if (rm.get("role").equals(J.get(ps.get(n), "role"))) hits.add(n);
        hits.sort(null);
        if (hits.size() != 1) throw bad(at + ": '" + d.get("verb") + "' has " + (hits.isEmpty() ? "no" : "several") + " parameter" + (hits.isEmpty() ? "" : "s") + " with role " + rm.get("role"));
        return J.obj("name", hits.get(0), "p", ps.get(hits.get(0)));
    }

    /** The money parameters of an action: {@code {amount, exp, ccy: {literal} | {param}}}. */
    public static Map<String, Object> moneyOf(Map<String, Object> d) {
        Map<String, Object> ps = params(d);
        List<String> hits = new ArrayList<>();
        for (String n : ps.keySet()) if ("money.amount".equals(J.get(ps.get(n), "role"))) hits.add(n);
        hits.sort(null);
        if (hits.size() != 1) throw bad("'" + d.get("verb") + "' needs exactly one parameter with role money.amount for an amount or approval-above rule (has " + hits.size() + ")");
        String name = hits.get(0);
        Map<String, Object> p = J.m(ps.get(name));
        if (!"integer".equals(p.get("type"))) throw bad("'" + d.get("verb") + "': the money.amount parameter '" + name + "' must be an integer");
        Object u = p.get("unit");
        if (u == null || !"money".equals(J.get(u, "kind"))) throw bad("'" + d.get("verb") + "': the amount parameter '" + name + "' declares no money unit (its currency)");
        Object ccy = J.get(u, "ccy");
        if (ccy instanceof String) return J.obj("amount", name, "exp", J.get(u, "exp"), "ccy", J.obj("literal", ccy));
        String from = (String) J.get(ccy, "from");
        if (!own(ps, from)) throw bad("'" + d.get("verb") + "': the currency parameter '" + from + "' does not exist");
        return J.obj("amount", name, "exp", J.get(u, "exp"), "ccy", J.obj("param", from));
    }

    private static int expOf(Map<String, Object> money) { return (int) J.num(money.get("exp")).doubleValue(); }

    private static boolean safeInt(double v) { return v == Math.rint(v) && Math.abs(v) <= 9007199254740991.0; }

    /** Integer minor units of a money value under exponent {@code exp}. Throws {@code bad_rules} for a non-integer or over-precise value. */
    public static long minorUnits(Object v, int exp, String at) {
        Double num = J.num(v);
        if (num != null) {
            if (!J.isInt(num) || num < 0) throw bad(at + ": an amount is a non-negative integer of minor units, or a decimal string");
            return num.longValue();
        }
        if (!(v instanceof String)) throw bad(at + ": an amount is a number of minor units or a decimal string");
        Matcher m = DEC_RE.matcher((String) v);
        if (!m.matches()) throw bad(at + ": '" + v + "' is not a decimal amount");
        String frac = m.group(2) == null ? "" : m.group(2);
        if (frac.length() > exp) throw bad(at + ": '" + v + "' has more decimals than the currency's " + exp);
        StringBuilder padded = new StringBuilder(frac);
        while (padded.length() < exp) padded.append('0');
        String f = padded.length() == 0 ? "0" : padded.toString();
        double n = Double.parseDouble(m.group(1)) * Math.pow(10, exp) + Double.parseDouble(f);
        if (!safeInt(n)) throw bad(at + ": '" + v + "' is too large");
        return (long) n;
    }

    private static int mins(String hhmm) { return Integer.parseInt(hhmm.substring(0, 2)) * 60 + Integer.parseInt(hhmm.substring(3, 5)); }

    private static ZoneId zoneOf(String tz) {
        if (tz == null || tz.isEmpty() || tz.length() > 64 || !tz.matches("[A-Za-z0-9_+\\-/]+")) return null;
        if (ZoneId.getAvailableZoneIds().contains(tz)) return ZoneId.of(tz);
        for (String z : ZoneId.getAvailableZoneIds()) if (z.equalsIgnoreCase(tz)) return ZoneId.of(z);
        return null;
    }

    /** Is this a time zone the runtime knows (IANA name)? */
    public static boolean knownTimeZone(Object tz) { return tz instanceof String && zoneOf((String) tz) != null; }

    /** Null iff {@code rules} is a well-formed rules block for {@code d}; the reason otherwise. */
    public static String businessRulesError(Map<String, Object> d, Object rules) {
        try {
            validateRules(d, rules);
            return null;
        } catch (RuntimeException e) {
            return e.getMessage();
        }
    }

    private static void ccyMap(Map<String, Object> d, Object m, String at) {
        if (!isObj(m) || J.m(m).isEmpty() || J.m(m).size() > MAX_RULE_CURRENCIES) throw bad(at + ": a map of 1.." + MAX_RULE_CURRENCIES + " currencies to amounts");
        Map<String, Object> money = moneyOf(d);
        for (Map.Entry<String, Object> e : J.m(m).entrySet()) {
            if (!CCY_RE.matcher(e.getKey()).matches()) throw bad(at + ": '" + e.getKey() + "' is not an ISO 4217 currency code");
            minorUnits(e.getValue(), expOf(money), at + "." + e.getKey());
        }
    }

    private static Map<String, Object> refOf(Map<String, Object> s) {
        Map<String, Object> r = new LinkedHashMap<>();
        if (own(s, "param")) r.put("param", s.get("param"));
        if (own(s, "role")) r.put("role", s.get("role"));
        return r;
    }

    private static boolean distinct(List<?> xs) { return new HashSet<>(xs).size() == xs.size(); }

    private static void validateRules(Map<String, Object> d, Object rules) {
        if (!isObj(rules)) throw bad("rules must be an object");
        Map<String, Object> r = J.m(rules);
        closed(r, RULE_KEYS, "rules");
        int n0 = 0;
        for (String k : r.keySet()) if (!k.equals("examples")) n0++;
        if (n0 == 0) throw bad("rules: name at least one rule");
        if (own(r, "amount")) {
            if (!isObj(r.get("amount"))) throw bad("rules.amount must be {max: {CCY: amount}}");
            closed(J.m(r.get("amount")), List.of("max"), "rules.amount");
            ccyMap(d, J.get(r.get("amount"), "max"), "rules.amount.max");
        }
        if (own(r, "approval")) {
            Object a = r.get("approval");
            if (!isObj(a)) throw bad("rules.approval must be an object");
            Map<String, Object> ap = J.m(a);
            closed(ap, List.of("above", "always", "approvers", "group"), "rules.approval");
            if (own(ap, "always") && !Boolean.TRUE.equals(ap.get("always"))) throw bad("rules.approval.always is true or absent");
            if (undef(ap, "above") == undef(ap, "always")) throw bad("rules.approval: give exactly one of above or always");
            if (own(ap, "above")) ccyMap(d, ap.get("above"), "rules.approval.above");
            if (own(ap, "approvers") && (!J.isInt(ap.get("approvers")) || J.num(ap.get("approvers")) < 1 || J.num(ap.get("approvers")) > MAX_RULE_APPROVERS)) throw bad("rules.approval.approvers is 1.." + MAX_RULE_APPROVERS);
            if (own(ap, "group") && !fullMatch(NAME_RE, ap.get("group"))) throw bad("rules.approval.group is a lowercase name");
        }
        if (own(r, "scope")) {
            Object sc = r.get("scope");
            if (!(sc instanceof List) || ((List<?>) sc).isEmpty() || ((List<?>) sc).size() > MAX_RULE_LIST) throw bad("rules.scope is a list of 1.." + MAX_RULE_LIST + " bindings");
            int i = 0;
            for (Object s0 : (List<?>) sc) {
                String at = "rules.scope[" + i + "]";
                if (!isObj(s0)) throw bad(at + " must be an object");
                Map<String, Object> s = J.m(s0);
                closed(s, List.of("param", "role", "caller"), at);
                Object p = resolveParamRef(d, refOf(s), at).get("p");
                Object ty = J.get(p, "type");
                if (!"string".equals(ty) && !"integer".equals(ty)) throw bad(at + ": the bound parameter must be a string or integer id");
                if (!fullMatch(NAME_RE, s.get("caller"))) throw bad(at + ".caller is a lowercase attribute name of the caller");
                i++;
            }
        }
        if (own(r, "rate")) {
            Object rt = r.get("rate");
            if (!(rt instanceof List) || ((List<?>) rt).isEmpty() || ((List<?>) rt).size() > 4) throw bad("rules.rate is a list of 1..4 limits");
            int i = 0;
            for (Object x0 : (List<?>) rt) {
                String at = "rules.rate[" + i + "]";
                if (!isObj(x0)) throw bad(at + " must be an object");
                Map<String, Object> x = J.m(x0);
                closed(x, List.of("max", "per", "by"), at);
                if (!J.isInt(x.get("max")) || J.num(x.get("max")) < 1 || J.num(x.get("max")) > 1_000_000) throw bad(at + ".max is 1..1000000");
                if (!RATE_PERIODS.containsKey(J.jsStr(x.get("per")))) throw bad(at + ".per is hour or day");
                if (own(x, "by") && !"principal".equals(x.get("by")) && !"org".equals(x.get("by"))) throw bad(at + ".by is principal or org");
                i++;
            }
        }
        if (own(r, "hours")) {
            if (!isObj(r.get("hours"))) throw bad("rules.hours must be an object");
            Map<String, Object> h = J.m(r.get("hours"));
            closed(h, List.of("days", "from", "to", "tz", "outside"), "rules.hours");
            Object days = h.get("days");
            boolean daysOk = days instanceof List && !((List<?>) days).isEmpty() && distinct((List<?>) days);
            if (daysOk) for (Object x : (List<?>) days) if (!(x instanceof String) || !RULE_DAYS.contains(x)) daysOk = false;
            if (!daysOk) throw bad("rules.hours.days is a list of distinct days (" + String.join(", ", RULE_DAYS) + ")");
            if (!fullMatch(HHMM_RE, h.get("from")) || !fullMatch(HHMM_RE, h.get("to"))) throw bad("rules.hours.from and .to are HH:MM (24 h)");
            if (!knownTimeZone(h.get("tz"))) throw bad("rules.hours.tz '" + J.jsStr(h.get("tz")) + "' is not a known IANA time zone");
            if (own(h, "outside") && !"escalate".equals(h.get("outside")) && !"deny".equals(h.get("outside"))) throw bad("rules.hours.outside is escalate or deny");
        }
        if (own(r, "recipients")) {
            if (!isObj(r.get("recipients"))) throw bad("rules.recipients must be an object");
            Map<String, Object> x = J.m(r.get("recipients"));
            closed(x, List.of("param", "role", "domains", "addresses"), "rules.recipients");
            Map<String, Object> res = resolveParamRef(d, refOf(x), "rules.recipients");
            String name = (String) res.get("name");
            Map<String, Object> p = J.m(res.get("p"));
            Object ty = p.get("type");
            if ("array".equals(ty) || "set".equals(ty)) {
                if (own(p, "items") && !"string".equals(p.get("items"))) throw bad("rules.recipients: '" + name + "' must hold strings");
                if (!J.isInt(p.get("max_items")) || J.num(p.get("max_items")) > MAX_RULE_LIST) throw bad("rules.recipients: the list parameter '" + name + "' needs max_items <= " + MAX_RULE_LIST + " so every entry can be checked");
            } else if (!"string".equals(ty)) throw bad("rules.recipients: '" + name + "' must be a string or a bounded list of strings");
            if (undef(x, "domains") && undef(x, "addresses")) throw bad("rules.recipients: give domains and/or addresses");
            if (own(x, "domains") && !listOf(x.get("domains"), DOMAIN_RE)) throw bad("rules.recipients.domains is a list of lowercase domain names");
            if (own(x, "addresses") && !listOf(x.get("addresses"), ADDRESS_RE)) throw bad("rules.recipients.addresses is a list of lowercase email addresses");
        }
        if (own(r, "required")) {
            Object rq = r.get("required");
            if (!(rq instanceof List) || ((List<?>) rq).isEmpty() || ((List<?>) rq).size() > MAX_RULE_LIST || !distinct((List<?>) rq)) throw bad("rules.required is a list of distinct parameter names");
            for (Object n : (List<?>) rq) if (!(n instanceof String) || !own(params(d), (String) n)) throw bad("rules.required: '" + d.get("verb") + "' has no parameter '" + J.jsStr(n) + "'");
        }
        if (own(r, "examples")) {
            Object ex = r.get("examples");
            if (!(ex instanceof List) || ((List<?>) ex).size() > MAX_RULE_EXAMPLES) throw bad("rules.examples is a list of at most " + MAX_RULE_EXAMPLES);
            int i = 0;
            for (Object e0 : (List<?>) ex) {
                String at = "rules.examples[" + i + "]";
                if (!isObj(e0)) throw bad(at + " must be an object");
                Map<String, Object> e = J.m(e0);
                closed(e, List.of("params", "caller", "at", "recent", "expect"), at);
                if (!isObj(e.get("params"))) throw bad(at + ".params must be an object");
                if (own(e, "caller") && !isObj(e.get("caller"))) throw bad(at + ".caller must be an object");
                if (own(e, "at") && (!(e.get("at") instanceof String) || Double.isNaN(parseUtc((String) e.get("at"))))) throw bad(at + ".at is an RFC 3339 UTC time (…Z)");
                if (own(e, "recent")) {
                    boolean ok = isObj(e.get("recent"));
                    if (ok) for (Object c : J.m(e.get("recent")).values()) if (!J.isInt(c) || J.num(c) < 0) ok = false;
                    if (!ok) throw bad(at + ".recent maps rate indexes to counts");
                }
                if (!List.of("allow", "escalate", "deny").contains(e.get("expect"))) throw bad(at + ".expect is allow, escalate or deny");
                i++;
            }
        }
    }

    private static boolean listOf(Object v, Pattern re) {
        if (!(v instanceof List) || ((List<?>) v).isEmpty() || ((List<?>) v).size() > MAX_RULE_LIST) return false;
        for (Object x : (List<?>) v) if (!fullMatch(re, x)) return false;
        return true;
    }

    /** {@code Date.parse} of an RFC 3339 UTC time ({@code ...Z}, whole seconds) as the reference engine reads it; NaN when it does not. */
    public static double parseUtc(String s) {
        Matcher m = AT_RE.matcher(s);
        if (!m.matches()) return Double.NaN;
        int y = Integer.parseInt(m.group(1)), mo = Integer.parseInt(m.group(2)), dd = Integer.parseInt(m.group(3));
        int h = Integer.parseInt(m.group(4)), mi = Integer.parseInt(m.group(5)), se = Integer.parseInt(m.group(6));
        if (mo < 1 || mo > 12 || dd < 1 || dd > 31 || h > 24 || mi > 59 || se > 59 || (h == 24 && (mi != 0 || se != 0))) return Double.NaN;
        long days = LocalDate.of(y, mo, 1).toEpochDay() + (dd - 1);
        return (double) (days * 86_400_000L + h * 3_600_000L + mi * 60_000L + se * 1000L);
    }

    // ---- compiled form -----------------------------------------------------------------------------------------------------------

    /** Digest of a rules block (examples are tests, not rules). */
    public static String businessRulesDigest(String verb, Map<String, Object> rules) {
        Map<String, Object> body = new LinkedHashMap<>(rules);
        body.remove("examples");
        return Pca.hashCanonical(J.obj("d", BUSINESS_RULES_DOMAIN, "verb", verb, "rules", body));
    }

    private static String P(String n) { return "action.params." + n; }

    private static Map<String, Object> cond(String field, String op, Object value) { return J.obj("field", field, "op", op, "value", value); }

    private static Map<String, Object> ccyCond(Map<String, Object> m, String c) {
        Map<String, Object> ccy = J.m(m.get("ccy"));
        if (ccy.containsKey("param")) return cond(P((String) ccy.get("param")), "eq", c);
        return c.equals(ccy.get("literal")) ? null : cond("action.verb", "eq", "\u0000never");
    }

    private static Map<String, Object> and(List<Map<String, Object>> cs) {
        List<Object> xs = new ArrayList<>();
        for (Map<String, Object> c : cs) if (c != null) xs.add(c);
        return xs.size() == 1 ? J.m(xs.get(0)) : J.obj("all_of", xs);
    }

    private static Map<String, Object> always(Object verb) { return cond("action.verb", "eq", verb); }

    private static String ruleId(String s) {
        String r = s.toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9_]", "_");
        return r.length() > 64 ? r.substring(0, 64) : r;
    }

    private static Map<String, Object> rule(String id, Object when, String signal, String reason) { return J.obj("id", id, "when", when, "signal", signal, "reason", reason); }

    private static List<Object> sortedStrings(Object xs) {
        List<Object> out = new ArrayList<>(J.a(xs));
        out.sort((a, b) -> ((String) a).compareTo((String) b));
        return out;
    }

    private static String listText(List<String> xs) { return String.join(", ", xs); }

    /** Compile a rules block for {@code d}. Throws ActionKitError {@code bad_rules} for a malformed block. Deterministic. */
    public static Map<String, Object> compileBusinessRules(Map<String, Object> d, Map<String, Object> rules) {
        validateRules(d, rules);
        List<Object> t = new ArrayList<>(), acc = new ArrayList<>();
        Object verb = d.get("verb");
        Map<String, Object> out = J.obj("v", J.n(1), "verb", verb, "rules_digest", businessRulesDigest((String) verb, rules), "def_digest", Actions.defDigest(d), "tighten", t, "accumulators", acc);
        Object approval = rules.get("approval");
        Map<String, Object> money = own(rules, "amount") || (approval != null && own(approval, "above")) ? moneyOf(d) : null;
        int exp = money == null ? 0 : expOf(money);
        if (own(rules, "amount")) {
            Map<String, Object> maxes = J.m(J.get(rules.get("amount"), "max"));
            List<String> listed = sortedKeys(maxes);
            for (String c : listed) {
                long max = minorUnits(maxes.get(c), exp, "rules.amount.max." + c);
                t.add(rule(ruleId("amount_max_" + c), and(java.util.Arrays.asList(ccyCond(money, c), cond(P((String) money.get("amount")), "gt", J.n(max)))), "deny", "the amount is above the " + formatMoney(max, c, exp) + " ceiling"));
            }
            Map<String, Object> u = unlisted(money, listed, verb);
            if (u != null) t.add(rule("amount_currency", u, "deny", "only " + listText(listed) + " amounts are allowed"));
        }
        if (own(rules, "approval")) {
            Map<String, Object> ap = J.m(approval);
            Map<String, Object> need = J.obj("approvers", own(ap, "approvers") ? ap.get("approvers") : J.n(1));
            if (own(ap, "group")) need.put("group", ap.get("group"));
            out.put("approval", need);
            if (Boolean.TRUE.equals(ap.get("always"))) t.add(rule("approval_always", always(verb), "escalate", "this action always needs approval"));
            else {
                Map<String, Object> above = J.m(ap.get("above"));
                List<String> listed = sortedKeys(above);
                for (String c : listed) {
                    long x = minorUnits(above.get(c), exp, "rules.approval.above." + c);
                    t.add(rule(ruleId("approval_above_" + c), and(java.util.Arrays.asList(ccyCond(money, c), cond(P((String) money.get("amount")), "gt", J.n(x)))), "escalate", "amounts above " + formatMoney(x, c, exp) + " need approval"));
                }
                Map<String, Object> u = unlisted(money, listed, verb);
                if (u != null) t.add(rule("approval_currency", u, "escalate", "amounts in a currency other than " + listText(listed) + " need approval"));
            }
        }
        if (own(rules, "scope")) {
            int i = 0;
            for (Object s0 : J.a(rules.get("scope"))) {
                Map<String, Object> s = J.m(s0);
                String name = (String) resolveParamRef(d, refOf(s), "rules.scope[" + i + "]").get("name");
                // `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
                Map<String, Object> eq = J.obj("field", P(name), "op", "eq", "ref", "subject." + s.get("caller"));
                t.add(rule("scope_" + i, J.obj("not", eq), "deny", name + " must be the caller's own " + s.get("caller")));
                i++;
            }
        }
        if (own(rules, "rate")) {
            int i = 0;
            for (Object r0 : J.a(rules.get("rate"))) {
                Map<String, Object> r = J.m(r0);
                String id = "rate_" + i, by = own(r, "by") ? (String) r.get("by") : "principal", per = J.jsStr(r.get("per"));
                acc.add(J.obj("id", id, "agg", "count", "sel", J.obj("verbs", J.list(verb)), "win", J.obj("kind", "sliding", "ms", J.n(RATE_PERIODS.get(per))),
                    "key", null, "domain_max", r.get("max"), "cap", r.get("max"), "holder", J.obj("kind", "site_local"), "scope", by));
                t.add(rule(id, cond("env.acc." + id, "gte", r.get("max")), "deny", "at most " + J.jsStr(r.get("max")) + " per " + per + " per " + by));
                i++;
            }
        }
        if (own(rules, "hours")) {
            Map<String, Object> h = J.m(rules.get("hours"));
            int from = mins((String) h.get("from")), to = mins((String) h.get("to"));
            List<Integer> dows = new ArrayList<>();
            for (Object x : J.a(h.get("days"))) dows.add(RULE_DAYS.indexOf(x));
            dows.sort(null);
            List<Object> dowsJ = new ArrayList<>(), nextJ = new ArrayList<>();
            for (int x : dows) { dowsJ.add(J.n(x)); nextJ.add(J.n((x + 1) % 7)); }
            Object inTime = from < to
                ? J.obj("all_of", J.list(cond("env.clock.min", "gte", J.n(from)), cond("env.clock.min", "lt", J.n(to))))
                : J.obj("any_of", J.list(cond("env.clock.min", "gte", J.n(from)), cond("env.clock.min", "lt", J.n(to))));
            Object day = from < to
                ? cond("env.clock.dow", "in", dowsJ)
                : J.obj("any_of", J.list(
                    J.obj("all_of", J.list(cond("env.clock.dow", "in", dowsJ), cond("env.clock.min", "gte", J.n(from)))),
                    J.obj("all_of", J.list(cond("env.clock.dow", "in", nextJ), cond("env.clock.min", "lt", J.n(to))))));
            out.put("clock_tz", h.get("tz"));
            t.add(rule("hours", J.obj("not", J.obj("all_of", J.list(day, inTime))), own(h, "outside") ? (String) h.get("outside") : "escalate", "outside " + hoursText(h)));
        }
        if (own(rules, "recipients")) {
            Map<String, Object> x = J.m(rules.get("recipients"));
            Map<String, Object> res = resolveParamRef(d, refOf(x), "rules.recipients");
            String name = (String) res.get("name");
            Map<String, Object> p = J.m(res.get("p"));
            Object ok;
            if ("string".equals(p.get("type"))) ok = okAt(x, P(name));
            else {
                int n = (int) J.num(p.get("max_items")).doubleValue();
                List<Object> all = new ArrayList<>();
                for (int i = 0; i < n; i++) all.add(J.obj("any_of", J.list(cond(P(name + "." + i), "exists", Boolean.FALSE), okAt(x, P(name + "." + i)))));
                all.add(cond(P(name + "." + n), "exists", Boolean.FALSE));
                ok = J.obj("all_of", all);
            }
            t.add(rule("recipients", J.obj("not", ok), "deny", name + " may only name " + recipientsText(x)));
        }
        if (own(rules, "required")) {
            int i = 0;
            for (Object n0 : J.a(rules.get("required"))) {
                String n = (String) n0;
                Object missing = "string".equals(J.get(params(d).get(n), "type"))
                    ? J.obj("any_of", J.list(cond(P(n), "exists", Boolean.FALSE), cond(P(n), "eq", "")))
                    : cond(P(n), "exists", Boolean.FALSE);
                t.add(rule("required_" + i, missing, "deny", n + " is required"));
                i++;
            }
        }
        for (Object r0 : t) {
            Map<String, Object> r = J.m(r0);
            String rs = (String) r.get("reason");
            if (rs != null && rs.length() > 256) r.put("reason", rs.substring(0, 253) + "...");
        }
        return out;
    }

    private static Map<String, Object> unlisted(Map<String, Object> money, List<String> listed, Object verb) {
        if (money == null) return null;
        Map<String, Object> ccy = J.m(money.get("ccy"));
        if (ccy.containsKey("param")) return J.obj("not", cond(P((String) ccy.get("param")), "in", J.objs(listed)));
        return listed.contains(ccy.get("literal")) ? null : always(verb);
    }

    private static Object okAt(Map<String, Object> x, String path) {
        List<Object> any = new ArrayList<>();
        if (own(x, "domains")) for (Object dm : J.a(x.get("domains"))) any.add(cond(path, "like", "*@" + ((String) dm).replaceAll("([\\\\*?])", "\\\\$1")));
        if (own(x, "addresses")) any.add(cond(path, "in", sortedStrings(x.get("addresses"))));
        return J.obj("any_of", any);
    }

    // ---- evaluation --------------------------------------------------------------------------------------------------------------

    /** Day of week (0 = Sunday) and minute of day at {@code now} in {@code tz}, or null when it cannot be computed. */
    public static Map<String, Object> clockAt(double now, String tz) {
        try {
            if (Double.isNaN(now) || Double.isInfinite(now) || Math.abs(now) > 8.64e15) return null;
            ZoneId z = zoneOf(tz);
            if (z == null) return null;
            ZonedDateTime t = Instant.ofEpochMilli((long) now).atZone(z);
            return J.obj("dow", J.n(t.getDayOfWeek().getValue() % 7), "min", J.n(t.getHour() * 60L + t.getMinute()));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static double nowOf(Map<String, Object> i) {
        Double n = J.num(i.get("now"));
        return n == null ? Double.NaN : n;
    }

    /** The predicate context the compiled rules are evaluated in. Verifier-computed {@code env} members only. */
    public static Map<String, Object> rulesContext(Map<String, Object> c, Map<String, Object> i) {
        Map<String, Object> env = new LinkedHashMap<>();
        if (own(c, "clock_tz")) {
            Map<String, Object> k = clockAt(nowOf(i), (String) c.get("clock_tz"));
            if (k != null) env.put("clock", k);
        }
        Map<String, Object> acc = new LinkedHashMap<>();
        Object counts = i.get("counts");
        for (Object a : J.a(c.get("accumulators"))) {
            Object id = J.get(a, "id");
            Object n = counts instanceof Map ? J.m(counts).get(id) : null;
            Double nd = J.num(n);
            if (nd != null && safeInt(nd) && nd >= 0) acc.put((String) id, n);
        }
        env.put("acc", acc);
        Object resource = i.get("resource");
        Map<String, Object> action = J.obj("verb", c.get("verb"), "resource", resource == null ? "" : resource, "params", i.get("params"));
        Object subject = i.get("subject");
        return J.obj("action", action, "subject", subject == null ? new LinkedHashMap<String, Object>() : subject, "env", env);
    }

    /** Evaluate compiled rules: {@code allow} unless a rule fires; a fired rule caps the decision at its signal. Never throws. */
    public static Map<String, Object> evaluateBusinessRules(Map<String, Object> c, Map<String, Object> i) {
        try {
            Map<String, Object> ctx = rulesContext(c, i);
            String decision = "allow";
            List<Object> reasons = new ArrayList<>(), fired = new ArrayList<>();
            boolean approval = false;
            for (Object r0 : J.a(c.get("tighten"))) {
                Map<String, Object> r = J.m(r0);
                if (Predicates.evaluateConditionTri(r.get("when"), ctx) == Predicates.Tri.FALSE) continue;
                decision = Decision.meet(decision, (String) r.get("signal"));
                fired.add(r.get("id"));
                reasons.add(r.get("id") + ": " + (r.get("reason") != null ? r.get("reason") : r.get("signal")));
                if ("escalate".equals(r.get("signal")) && ((String) r.get("id")).startsWith("approval_")) approval = true;
            }
            Map<String, Object> out = J.obj("decision", decision, "reasons", reasons, "fired", fired);
            if (approval && c.get("approval") != null) out.put("approval", c.get("approval"));
            return out;
        } catch (RuntimeException e) {
            return J.obj("decision", "deny", "reasons", J.list("rules: evaluation error (fail closed): " + e.getMessage()), "fired", new ArrayList<Object>());
        }
    }

    /** The decision with rules applied to a base decision: the meet, so rules never raise it. */
    public static String withBusinessRules(String base, Map<String, Object> verdict) { return Decision.meet(base, (String) verdict.get("decision")); }

    /** Run a rules block's examples: a list of {@code {index, expect, got, ok, why}}. */
    public static List<Object> runRuleExamples(Map<String, Object> d, Map<String, Object> rules) {
        Map<String, Object> c = compileBusinessRules(d, rules);
        List<Object> out = new ArrayList<>();
        if (!own(rules, "examples")) return out;
        int index = 0;
        for (Object e0 : J.a(rules.get("examples"))) {
            Map<String, Object> e = J.m(e0);
            Map<String, Object> counts = new LinkedHashMap<>();
            int k = 0;
            for (Object a : J.a(c.get("accumulators"))) {
                Object rec = e.get("recent");
                Object v = rec instanceof Map ? J.m(rec).get(String.valueOf(k)) : null;
                counts.put((String) J.get(a, "id"), v == null ? J.n(0) : v);
                k++;
            }
            Map<String, Object> in = J.obj("params", e.get("params"));
            if (e.get("caller") != null) in.put("subject", e.get("caller"));
            double now = own(e, "at") && e.get("at") != null ? parseUtc((String) e.get("at")) : parseUtc("2026-01-07T15:00:00Z");
            in.put("now", new Json.Num(net.atlasauth.pca.AttestCommon.jsNumString(now)));
            in.put("counts", counts);
            Map<String, Object> v = evaluateBusinessRules(c, in);
            boolean ok = v.get("decision").equals(e.get("expect"));
            String why = String.join("; ", strs(v.get("reasons")));
            out.add(J.obj("index", J.n(index), "expect", e.get("expect"), "got", v.get("decision"), "ok", ok, "why", why.isEmpty() ? "no rule fired" : why));
            index++;
        }
        return out;
    }

    private static List<String> strs(Object xs) {
        List<String> out = new ArrayList<>();
        for (Object x : J.a(xs)) out.add((String) x);
        return out;
    }

    // ---- plain language ----------------------------------------------------------------------------------------------------------

    /** {@code 12345} minor units of USD (exp 2) is "123.45 USD". Deterministic (no locale). */
    public static String formatMoney(long minor, String ccy, int exp) {
        StringBuilder s = new StringBuilder(Long.toString(minor));
        while (s.length() < exp + 1) s.insert(0, '0');
        String str = s.toString();
        return (exp > 0 ? str.substring(0, str.length() - exp) + "." + str.substring(str.length() - exp) : str) + " " + ccy;
    }

    private static String hoursText(Map<String, Object> h) {
        List<Integer> idx = new ArrayList<>();
        for (Object x : J.a(h.get("days"))) idx.add(RULE_DAYS.indexOf(x));
        idx.sort(null);
        boolean run = idx.size() > 2;
        for (int k = 1; k < idx.size(); k++) if (idx.get(k) != idx.get(k - 1) + 1) run = false;
        String days;
        if (run) days = DAY_NAMES.get(idx.get(0)) + "-" + DAY_NAMES.get(idx.get(idx.size() - 1));
        else {
            List<String> ns = new ArrayList<>();
            for (int x : idx) ns.add(DAY_NAMES.get(x));
            days = String.join(", ", ns);
        }
        return days + " " + h.get("from") + "-" + h.get("to") + " (" + h.get("tz") + ")";
    }

    private static String recipientsText(Map<String, Object> x) {
        List<String> parts = new ArrayList<>();
        if (own(x, "domains")) for (Object dm : J.a(x.get("domains"))) parts.add("addresses at " + dm);
        if (own(x, "addresses")) for (Object a : J.a(x.get("addresses"))) parts.add((String) a);
        return String.join(" or ", parts);
    }

    private static String moneyList(Map<String, Object> mp, int exp) {
        List<String> out = new ArrayList<>();
        for (String c : sortedKeys(mp)) out.add(formatMoney(minorUnits(mp.get(c), exp, c), c, exp));
        return String.join(", ", out);
    }

    /** One plain sentence per rule. Throws {@code bad_rules} for a malformed block. */
    public static List<Object> explainBusinessRules(Map<String, Object> d, Map<String, Object> rules) {
        validateRules(d, rules);
        List<Object> out = new ArrayList<>();
        Object approval = rules.get("approval");
        Map<String, Object> m = own(rules, "amount") || (approval != null && own(approval, "above")) ? moneyOf(d) : null;
        int exp = m == null ? 0 : expOf(m);
        if (own(rules, "amount")) out.add("Refuses amounts above " + moneyList(J.m(J.get(rules.get("amount"), "max")), exp) + "; any other currency is refused.");
        if (approval != null) {
            Map<String, Object> ap = J.m(approval);
            double n = own(ap, "approvers") ? J.num(ap.get("approvers")) : 1;
            String cnt = net.atlasauth.pca.AttestCommon.jsNumString(n);
            String who = cnt + " approver" + (n == 1 ? "" : "s") + (own(ap, "group") && !"".equals(ap.get("group")) ? " from the " + ap.get("group") + " group" : "");
            out.add(Boolean.TRUE.equals(ap.get("always")) ? "Always needs approval by " + who + "." : "Needs approval by " + who + " when the amount is above " + moneyList(J.m(ap.get("above")), exp) + " (or in another currency).");
        }
        if (own(rules, "scope")) for (Object s0 : J.a(rules.get("scope"))) {
            Map<String, Object> s = J.m(s0);
            String name = (String) resolveParamRef(d, refOf(s), "rules.scope").get("name");
            out.add("Only the caller's own records: " + name + " must be the caller's " + s.get("caller") + ".");
        }
        if (own(rules, "rate")) for (Object r0 : J.a(rules.get("rate"))) {
            Map<String, Object> r = J.m(r0);
            out.add("At most " + J.jsStr(r.get("max")) + " per " + J.jsStr(r.get("per")) + " per " + ("org".equals(r.get("by")) ? "organisation" : "principal") + ".");
        }
        if (own(rules, "hours")) {
            Map<String, Object> h = J.m(rules.get("hours"));
            out.add("Only " + hoursText(h) + "; outside those hours it " + ("deny".equals(h.get("outside")) ? "is refused" : "needs approval") + ".");
        }
        if (own(rules, "recipients")) {
            Map<String, Object> x = J.m(rules.get("recipients"));
            String name = (String) resolveParamRef(d, refOf(x), "rules.recipients").get("name");
            out.add(name + " may only name " + recipientsText(x) + ".");
        }
        if (own(rules, "required")) out.add("Requires " + listText(strs(rules.get("required"))) + ".");
        return out;
    }

    // ---- lint --------------------------------------------------------------------------------------------------------------------

    /** The rules lints (ids LR-*): {@code [id, severity, title]}. */
    public static final List<String[]> BUSINESS_RULE_LINTS = List.of(
        new String[] {"LR-001", "error", "a rules block is malformed or names a parameter the action does not have"},
        new String[] {"LR-002", "error", "a contradiction: under the rules the action can never be allowed"},
        new String[] {"LR-003", "warning", "a rule that can never fire or that another rule already covers"},
        new String[] {"LR-004", "error", "a rules example does not decide as it expects"});

    private static Map<String, Object> finding(Map<String, Object> d, String rule, String severity, String message) {
        return J.obj("rule", rule, "severity", severity, "verb", d.get("verb"), "message", message);
    }

    private static String ccyJoin(List<Object> xs) {
        List<String> out = new ArrayList<>();
        for (Object x : xs) out.add(J.jsStr(x));
        return String.join(", ", out);
    }

    private static String numStr(Object n) { return J.jsStr(n); }

    /** Lint one action's rules. */
    public static List<Object> lintBusinessRules(Map<String, Object> d, Object rules) {
        List<Object> out = new ArrayList<>();
        String e = businessRulesError(d, rules);
        if (e != null) { out.add(finding(d, "LR-001", "error", e)); return out; }
        Map<String, Object> r = J.m(rules);
        Object approval = r.get("approval");
        Map<String, Object> ps = params(d);
        boolean above = approval != null && own(approval, "above");
        Map<String, Object> m = own(r, "amount") || above ? moneyOf(d) : null;
        int exp = m == null ? 0 : expOf(m);
        Map<String, Object> amt = m == null ? null : J.m(ps.get((String) m.get("amount")));
        List<Object> ccyValues = null;
        if (m != null) {
            Map<String, Object> ccy = J.m(m.get("ccy"));
            ccyValues = ccy.containsKey("param") ? (J.get(ps.get((String) ccy.get("param")), "values") instanceof List ? J.a(J.get(ps.get((String) ccy.get("param")), "values")) : null) : J.list(ccy.get("literal"));
        }
        if (own(r, "amount") && m != null) {
            Map<String, Object> maxes = J.m(J.get(r.get("amount"), "max"));
            List<String> listed = new ArrayList<>(maxes.keySet());
            if (ccyValues != null) {
                boolean any = false;
                for (Object c : ccyValues) if (listed.contains(c)) any = true;
                if (!any) out.add(finding(d, "LR-002", "error", "rules.amount: none of the action's currencies (" + ccyJoin(ccyValues) + ") has a ceiling, so every call is refused"));
            }
            for (String c : listed) {
                long max = minorUnits(maxes.get(c), exp, c);
                if (ccyValues != null && !ccyValues.contains(c)) out.add(finding(d, "LR-003", "warning", "rules.amount.max." + c + ": the action never uses " + c));
                if (amt != null && own(amt, "min") && max < J.num(amt.get("min"))) out.add(finding(d, "LR-002", "error", "rules.amount.max." + c + ": the ceiling " + formatMoney(max, c, exp) + " is below the parameter's minimum, so every " + c + " call is refused"));
                if (amt != null && own(amt, "max") && max >= J.num(amt.get("max"))) out.add(finding(d, "LR-003", "warning", "rules.amount.max." + c + ": the parameter's own maximum already bounds the amount below this ceiling"));
            }
        }
        if (above && m != null) {
            Map<String, Object> ab = J.m(J.get(approval, "above"));
            Object amount = own(r, "amount") ? J.get(r.get("amount"), "max") : null;
            for (String c : new ArrayList<>(ab.keySet())) {
                long x = minorUnits(ab.get(c), exp, c);
                Object ceil = amount instanceof Map ? J.m(amount).get(c) : null;
                if (ceil != null && x >= minorUnits(ceil, exp, c)) out.add(finding(d, "LR-003", "warning", "rules.approval.above." + c + ": above the amount ceiling, so the approval can never be asked for"));
                if (own(r, "amount") && ceil == null) out.add(finding(d, "LR-003", "warning", "rules.approval.above." + c + ": " + c + " has no ceiling, so it is always refused before an approval"));
            }
        }
        if (own(r, "hours")) {
            Map<String, Object> h = J.m(r.get("hours"));
            if (h.get("from").equals(h.get("to"))) out.add(finding(d, "LR-002", "error", "rules.hours: the window " + h.get("from") + "-" + h.get("to") + " is empty, so the action is " + ("deny".equals(h.get("outside")) ? "always refused" : "always escalated")));
        }
        if (own(r, "required")) for (Object n : J.a(r.get("required"))) {
            Map<String, Object> p = J.m(ps.get((String) n));
            if (!Boolean.FALSE.equals(p.get("required")) && !"string".equals(p.get("type"))) out.add(finding(d, "LR-003", "warning", "rules.required: '" + n + "' is already required by the definition"));
        }
        if (own(r, "rate")) {
            Map<String, Double> seen = new HashMap<>();
            for (Object x0 : J.a(r.get("rate"))) {
                Map<String, Object> x = J.m(x0);
                String per = J.jsStr(x.get("per")), by = own(x, "by") ? (String) x.get("by") : "principal", k = per + "|" + by;
                double mx = J.num(x.get("max"));
                if (seen.containsKey(k)) out.add(finding(d, "LR-003", "warning", "rules.rate: two limits per " + per + " per " + by + "; only the lower (" + net.atlasauth.pca.AttestCommon.jsNumString(Math.min(seen.get(k), mx)) + ") matters"));
                seen.put(k, Math.min(seen.getOrDefault(k, Double.POSITIVE_INFINITY), mx));
            }
            Double hh = seen.get("hour|principal"), dd = seen.get("day|principal");
            if (hh != null && dd != null && dd <= hh) out.add(finding(d, "LR-003", "warning", "rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires"));
        }
        try {
            for (Object x0 : runRuleExamples(d, r)) {
                Map<String, Object> x = J.m(x0);
                if (!Boolean.TRUE.equals(x.get("ok"))) out.add(finding(d, "LR-004", "error", "rules.examples[" + numStr(x.get("index")) + "]: expected " + x.get("expect") + ", got " + x.get("got") + " (" + x.get("why") + ")"));
            }
        } catch (RuntimeException err) {
            out.add(finding(d, "LR-001", "error", err.getMessage()));
        }
        return out;
    }

    // ---- semantic diff of rules --------------------------------------------------------------------------------------------------

    private enum Rel { EQ, NARROW, WIDEN, INC }

    private static String relName(Rel r) { return r == Rel.INC ? "incomparable" : r.name().toLowerCase(java.util.Locale.ROOT); }

    private static Rel setRel(Iterable<?> a, Iterable<?> b) {
        Set<Object> A = new HashSet<>(), B = new HashSet<>();
        for (Object x : a) A.add(x);
        for (Object x : b) B.add(x);
        boolean aInB = B.containsAll(A), bInA = A.containsAll(B);
        return aInB && bInA ? Rel.EQ : bInA ? Rel.NARROW : aInB ? Rel.WIDEN : Rel.INC;
    }

    private static Rel numRel(double a, double b) { return a == b ? Rel.EQ : b < a ? Rel.NARROW : Rel.WIDEN; }

    private static Rel presence(Map<String, Object> o, Map<String, Object> n, String k) {
        boolean a = undef(o, k), b = undef(n, k);
        return a && b ? Rel.EQ : a ? Rel.NARROW : b ? Rel.WIDEN : null;
    }

    private static Rel combine(List<Rel> rs) {
        boolean inc = rs.contains(Rel.INC), nar = rs.contains(Rel.NARROW), wid = rs.contains(Rel.WIDEN);
        return inc || (nar && wid) ? Rel.INC : wid ? Rel.WIDEN : nar ? Rel.NARROW : Rel.EQ;
    }

    private static Rel flip(Rel r) { return r == Rel.NARROW ? Rel.WIDEN : r == Rel.WIDEN ? Rel.NARROW : r; }

    private static Rel ccyMapRel(Object a, Object b, int exp) {
        Map<String, Object> A = J.m(a), B = J.m(b);
        List<Rel> rs = new ArrayList<>();
        rs.add(setRel(A.keySet(), B.keySet()));
        for (String c : A.keySet()) if (B.containsKey(c)) rs.add(numRel(minorUnits(A.get(c), exp, c), minorUnits(B.get(c), exp, c)));
        return combine(rs);
    }

    private static Set<Integer> minutesOfWeek(Map<String, Object> h) {
        Set<Integer> s = new HashSet<>();
        int from = mins((String) h.get("from")), to = mins((String) h.get("to"));
        for (Object day : J.a(h.get("days"))) {
            int base = RULE_DAYS.indexOf(day) * 1440;
            if (from < to) for (int x = from; x < to; x++) s.add(base + x);
            else if (from > to) {
                for (int x = from; x < 1440; x++) s.add(base + x);
                for (int x = 0; x < to; x++) s.add(((base + 1440) % 10080) + x);
            }
        }
        return s;
    }

    private static Map<String, Double> bestRates(Object rs) {
        Map<String, Double> mp = new HashMap<>();
        if (rs instanceof List) for (Object x0 : (List<?>) rs) {
            Map<String, Object> x = J.m(x0);
            String k = J.jsStr(x.get("per")) + "|" + (own(x, "by") ? J.jsStr(x.get("by")) : "principal");
            mp.put(k, Math.min(mp.getOrDefault(k, Double.POSITIVE_INFINITY), J.num(x.get("max"))));
        }
        return mp;
    }

    private static List<String> scopeKeys(Object sc) {
        List<String> out = new ArrayList<>();
        if (sc instanceof List) for (Object s0 : (List<?>) sc) {
            Map<String, Object> s = J.m(s0);
            out.add((s.get("param") == null ? "" : J.jsStr(s.get("param"))) + "|" + (s.get("role") == null ? "" : J.jsStr(s.get("role"))) + "|" + J.jsStr(s.get("caller")));
        }
        return out;
    }

    private static List<Object> listOrEmpty(Object x) { return x instanceof List ? J.a(x) : new ArrayList<>(); }

    private static List<String> allowed(Map<String, Object> x) {
        List<String> out = new ArrayList<>();
        for (Object dm : listOrEmpty(x.get("domains"))) out.add("@" + dm);
        for (Object a : listOrEmpty(x.get("addresses"))) out.add((String) a);
        return out;
    }

    private static boolean covered(String x, List<String> set) {
        if (set.contains(x)) return true;
        if (x.startsWith("@")) return false;
        String[] parts = x.split("@", -1);
        return parts.length > 1 && set.contains("@" + parts[1]);
    }

    /**
     * The semantic diff of two rules blocks of one action (either may be absent). {@code narrow} and {@code equal} can be published without
     * a reviewer; {@code widen} and {@code incomparable} need a reviewer's signed rules review. Returns {@code {class, reasons}}.
     */
    public static Map<String, Object> diffBusinessRules(Map<String, Object> d, Map<String, Object> prev, Map<String, Object> next) {
        List<Object[]> rels = new ArrayList<>();
        Map<String, Object> o = prev == null ? new LinkedHashMap<>() : prev, n = next == null ? new LinkedHashMap<>() : next;
        Map<String, Object> m = (own(o, "amount") || own(n, "amount") || (own(o, "approval") && own(o.get("approval"), "above")) || (own(n, "approval") && own(n.get("approval"), "above"))) ? moneyOf(d) : null;
        int exp = m == null ? 0 : expOf(m);

        Rel pr = presence(o, n, "amount");
        rels.add(new Object[] {"amount", pr != null ? pr : ccyMapRel(J.get(o.get("amount"), "max"), J.get(n.get("amount"), "max"), exp)});

        pr = presence(o, n, "approval");
        if (pr == null) {
            Map<String, Object> a = J.m(o.get("approval")), b = J.m(n.get("approval"));
            List<Rel> rs = new ArrayList<>();
            boolean aa = Boolean.TRUE.equals(a.get("always")), ba = Boolean.TRUE.equals(b.get("always"));
            if (aa && ba) rs.add(Rel.EQ);
            else if (aa) rs.add(Rel.WIDEN);
            else if (ba) rs.add(Rel.NARROW);
            else rs.add(ccyMapRel(a.get("above"), b.get("above"), exp));
            rs.add(numRel(-(own(a, "approvers") ? J.num(a.get("approvers")) : 1), -(own(b, "approvers") ? J.num(b.get("approvers")) : 1)));
            rs.add(java.util.Objects.equals(a.get("group"), b.get("group")) ? Rel.EQ : Rel.INC);
            pr = combine(rs);
        }
        rels.add(new Object[] {"approval", pr});

        rels.add(new Object[] {"scope", flip(setRel(scopeKeys(o.get("scope")), scopeKeys(n.get("scope"))))});

        Map<String, Double> A = bestRates(o.get("rate")), B = bestRates(n.get("rate"));
        Set<String> keys = new HashSet<>(A.keySet());
        keys.addAll(B.keySet());
        List<Rel> rr = new ArrayList<>();
        for (String k : keys) rr.add(!A.containsKey(k) ? Rel.NARROW : !B.containsKey(k) ? Rel.WIDEN : numRel(A.get(k), B.get(k)));
        rels.add(new Object[] {"rate", combine(rr)});

        pr = presence(o, n, "hours");
        if (pr == null) {
            Map<String, Object> a = J.m(o.get("hours")), b = J.m(n.get("hours"));
            if (!java.util.Objects.equals(a.get("tz"), b.get("tz"))) pr = Rel.INC;
            else {
                Set<Integer> sa = minutesOfWeek(a), sb = minutesOfWeek(b);
                Rel inner = sa.equals(sb) ? Rel.EQ : sa.containsAll(sb) ? Rel.NARROW : sb.containsAll(sa) ? Rel.WIDEN : Rel.INC;
                Rel outside = numRel("deny".equals(a.get("outside")) ? 0 : 1, "deny".equals(b.get("outside")) ? 0 : 1);
                pr = combine(List.of(inner, outside));
            }
        }
        rels.add(new Object[] {"hours", pr});

        pr = presence(o, n, "recipients");
        if (pr == null) {
            Map<String, Object> a = J.m(o.get("recipients")), b = J.m(n.get("recipients"));
            if (!java.util.Objects.equals(a.get("param"), b.get("param")) || !java.util.Objects.equals(a.get("role"), b.get("role"))) pr = Rel.INC;
            else {
                List<String> allowedA = allowed(a), allowedB = allowed(b);
                boolean bInA = true, aInB = true;
                for (String x : allowedB) if (!covered(x, allowedA)) bInA = false;
                for (String x : allowedA) if (!covered(x, allowedB)) aInB = false;
                pr = bInA && aInB ? Rel.EQ : bInA ? Rel.NARROW : aInB ? Rel.WIDEN : Rel.INC;
            }
        }
        rels.add(new Object[] {"recipients", pr});

        rels.add(new Object[] {"required", flip(setRel(listOrEmpty(o.get("required")), listOrEmpty(n.get("required"))))});

        List<Rel> diffRels = new ArrayList<>();
        TreeSet<String> reasons = new TreeSet<>();
        List<String> reasonList = new ArrayList<>();
        for (Object[] kv : rels) {
            Rel r = (Rel) kv[1];
            if (r == Rel.EQ) continue;
            diffRels.add(r);
            reasonList.add("rules." + kv[0] + ": " + relName(r));
        }
        reasonList.sort(null);
        Rel cls = combine(diffRels);
        return J.obj("class", cls == Rel.EQ ? "equal" : cls == Rel.INC ? "incomparable" : relName(cls), "reasons", new ArrayList<Object>(reasonList));
    }

    // ---- the reviewer's signature over a widened rules block --------------------------------------------------------------------

    /** The bytes a reviewer signs: the domain, a NUL, then the strict canonical body. */
    public static byte[] rulesReviewMessage(Map<String, Object> b) {
        Map<String, Object> body = J.obj("verb", b.get("verb"), "def_digest", b.get("def_digest"), "rules_digest", b.get("rules_digest"), "reviewer_kid", b.get("reviewer_kid"), "ts", b.get("ts"));
        byte[] dom = (RULES_REVIEW_DOMAIN + "\0").getBytes(StandardCharsets.UTF_8), bd = Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[dom.length + bd.length];
        System.arraycopy(dom, 0, out, 0, dom.length);
        System.arraycopy(bd, 0, out, dom.length, bd.length);
        return out;
    }

    /** Sign a rules review ({@code verb, def_digest, rules_digest, reviewer_kid, ts}) with an Ed25519 seed. */
    public static Map<String, Object> signRulesReview(Map<String, Object> b, byte[] secret) {
        Map<String, Object> out = new LinkedHashMap<>(b);
        out.put("sig", Keys.b64u(Keys.edFromSeed(secret).sign(rulesReviewMessage(b))));
        return out;
    }

    /**
     * Null iff {@code r} is a valid review of exactly these rules on exactly this def: digests match, the signer is pinned with the
     * {@code reviewer} role, the time is inside the key validity, the signature verifies. A reason otherwise. Never throws.
     */
    public static String rulesReviewError(Object r, Map<String, Object> d, Map<String, Object> rules, Object pins) {
        try {
            if (pins == null) return "no reviewer keys are pinned";
            String pe = ActionConfirmation.reviewerPinsError(pins);
            if (pe != null) return "bad pins: " + pe;
            if (!isObj(r)) return "no rules review";
            Map<String, Object> x = J.m(r);
            if (!d.get("verb").equals(x.get("verb"))) return "the rules review names another action";
            if (!Actions.defDigest(d).equals(x.get("def_digest"))) return "the rules review covers another version of the action";
            if (!businessRulesDigest((String) d.get("verb"), rules).equals(x.get("rules_digest"))) return "the rules review covers other rules";
            if (!(x.get("sig") instanceof String) || !(x.get("reviewer_kid") instanceof String) || !J.isInt(x.get("ts"))) return "malformed rules review";
            Map<String, Object> key = null;
            for (Object k : J.a(J.get(pins, "keys"))) if (x.get("reviewer_kid").equals(J.get(k, "kid"))) { key = J.m(k); break; }
            if (key == null) return "no pinned key '" + x.get("reviewer_kid") + "'";
            if (!J.a(key.get("roles")).contains("reviewer")) return "key '" + key.get("kid") + "' does not hold the reviewer role";
            double ts = J.num(x.get("ts"));
            if ((own(key, "not_before") && ts < J.num(key.get("not_before"))) || (own(key, "not_after") && ts > J.num(key.get("not_after")))) return "the review time is outside the key validity";
            Map<String, Object> body = new LinkedHashMap<>(x);
            body.remove("sig");
            byte[] pk = Pca.decodeB64uStrict(key.get("pk"), 32), sg = Pca.decodeB64uStrict(x.get("sig"), 64);
            return pk != null && sg != null && EdStrict.verify(pk, rulesReviewMessage(body), sg) ? null : "the rules review signature is invalid";
        } catch (RuntimeException e) {
            return "malformed rules review: " + e.getMessage();
        }
    }
}
