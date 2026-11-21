package net.atlasauth.pca.wallet;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.oauth.JsVal;

/**
 * The trusted question card. Rendering belongs to the wallet and is deterministic: {@link #renderCard} is a pure function of the
 * wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement, schema
 * units, the friction tier and (for a clarification) a closed-enum reason. Its input has NO field for agent-authored text. Values
 * of the concrete action are shown only in fixed slots: numbers formatted by unit, and a string only when the outcome space names
 * it (otherwise only its last four letters or digits). The card's digest goes into the signed answer, so an auditor can re-render
 * the card and see exactly what the human saw.
 */
public final class WalletCard {
    private WalletCard() {}

    public static final String CARD_DOMAIN = "atlas-pca/intent-card/v2";

    /** The closed reason enum of an agent clarification, with the fixed label the card shows. */
    public static final List<String> CLARIFY_REASONS = List.of("ambiguous_parameter", "multiple_options", "price_changed", "constraint_conflict", "missing_value", "other");

    public static final Map<String, String> REASON_LABELS = Map.of(
        "ambiguous_parameter", "Your agent found a detail your request did not settle.",
        "multiple_options", "Your agent found several options that match.",
        "price_changed", "Your agent found that a price changed.",
        "constraint_conflict", "Your agent found that two parts of your request conflict.",
        "missing_value", "Your agent needs a value your request did not give.",
        "other", "Your agent needs a decision before it continues.");

    // ---- text helpers ---------------------------------------------------------------------------------------------------

    private static final String WS = "[ \\f\\n\\r\\t\\u000b\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]";
    private static final Pattern CONTROL = Pattern.compile("[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2066-\\u2069]");
    private static final Pattern WS_RUN = Pattern.compile(WS + "+");
    private static final Pattern WS_ENDS = Pattern.compile("^" + WS + "+|" + WS + "+$");

    /** Strip control characters, collapse whitespace, cap length. For the principal's own words and the site's name. */
    public static String cleanText(String s, int max) {
        String t = CONTROL.matcher(s).replaceAll(" ");
        t = WS_RUN.matcher(t).replaceAll(" ");
        t = WS_ENDS.matcher(t).replaceAll("");
        return t.length() <= max ? t : t.substring(0, max - 1) + "…";
    }

    private static final Pattern NOT_ALNUM = Pattern.compile("[^A-Za-z0-9]");

    /** The last four letters / digits of a string (all a card ever shows of a string the outcome space does not name). */
    public static String last4(String s) {
        String t = NOT_ALNUM.matcher(s).replaceAll("");
        return (t.length() > 4 ? t.substring(t.length() - 4) : t).toUpperCase(java.util.Locale.ROOT);
    }

    /** The JavaScript decimal text of an integral double (plain digits), else the shortest form. */
    static String jsNum(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return Double.toString(d);
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new BigDecimal(d).toBigInteger().toString();
        return new BigDecimal(Double.toString(d)).toPlainString();
    }

    /** Thousands grouping with commas, independent of any locale. */
    private static String group(double n) {
        String s = jsNum(n);
        if (!s.matches("\\d+")) return s;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            if (i > 0 && (s.length() - i) % 3 == 0) sb.append(',');
            sb.append(s.charAt(i));
        }
        return sb.toString();
    }

    private static final Map<String, String> CURRENCY_SYMBOL = Map.of("USD", "$", "EUR", "€", "GBP", "£", "JPY", "¥");

    private static double trunc(double x) { return x < 0 ? Math.ceil(x) : Math.floor(x); }

    private static boolean isMoney(Object unit) { return unit instanceof Map && "money".equals(((Map<?, ?>) unit).get("kind")); }

    /** The exponent clamped to 0..6 as the reference does; NaN (a non-numeric member) stays NaN. */
    private static double exponentOf(Object unit) {
        Map<?, ?> um = (Map<?, ?>) unit;
        double e = Math.floor(jsToNumber(um.get("exponent"), um.containsKey("exponent")));
        return Double.isNaN(e) ? e : Math.max(0, Math.min(6, e));
    }

    /** String(v) of a JSON value; an absent member is "undefined". */
    static String jsStr(Object v, boolean present) {
        if (!present) return "undefined";
        if (v == null) return "null";
        Double n = JsVal.num(v);
        if (n != null) return jsNum(n);
        if (v instanceof Map) return "[object Object]";
        if (v instanceof List) {
            List<String> parts = new ArrayList<>();
            for (Object x : (List<?>) v) parts.add(x == null ? "" : jsStr(x, true));
            return String.join(",", parts);
        }
        return String.valueOf(v);
    }

    /** Number(v) of a JSON value; an absent member is NaN. */
    private static double jsToNumber(Object v, boolean present) {
        if (!present) return Double.NaN;
        if (v == null) return 0;
        Double n = JsVal.num(v);
        if (n != null) return n;
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        if (v instanceof Map) return Double.NaN;
        String t = jsStr(v, true).strip();
        if (t.isEmpty()) return 0;
        return t.matches("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?") ? Double.parseDouble(t) : Double.NaN;
    }

    /** A number as the card shows it: grouped, with the currency symbol and minor-unit decimals for money. */
    public static String formatNumber(double x, Object unit) {
        if (isMoney(unit)) {
            double e = exponentOf(unit);
            boolean neg = x < 0;
            double a = Math.abs(trunc(x));
            double div = Math.pow(10, e);
            String whole = group(Math.floor(a / div));
            String frac = "";
            if (e > 0) {
                String f = jsNum(a % div);
                StringBuilder pad = new StringBuilder();
                for (int i = f.length(); i < e; i++) pad.append('0');
                frac = "." + pad + f;
            }
            Map<?, ?> um = (Map<?, ?>) unit;
            String cur = jsStr(um.get("currency"), um.containsKey("currency"));
            String sym = CURRENCY_SYMBOL.containsKey(cur) ? CURRENCY_SYMBOL.get(cur) : cur + " ";
            return (neg ? "-" : "") + sym + whole + frac;
        }
        return (x < 0 ? "-" : "") + group(Math.abs(trunc(x)));
    }

    private static final Pattern ACC = Pattern.compile("env\\.acc\\.([A-Za-z0-9_.-]+)\\.post");
    private static final Pattern WORLD = Pattern.compile("env\\.world\\.([A-Za-z0-9_.-]+)");
    private static final Pattern MON = Pattern.compile("env\\.mon\\.([A-Za-z0-9_.-]+)\\.state");

    private static String spaced(String s) { return s.replace('_', ' ').replace('.', ' '); }

    static String dimLabel(String path) {
        Matcher m = ACC.matcher(path);
        if (m.matches()) return spaced(m.group(1)) + " (running total for this task)";
        m = WORLD.matcher(path);
        if (m.matches()) return spaced(m.group(1)) + " (from a signed fact)";
        m = MON.matcher(path);
        if (m.matches()) return "state of " + spaced(m.group(1));
        return WalletOmega.labelOf(path);
    }

    private static boolean isProvPath(String p) { return p.startsWith("env.prov."); }

    private static String numFact(Map<String, Object> d, int[] ids, Object unit, Object actionValue) {
        List<double[]> cells = WalletOmega.numCells(d);
        double lo = cells.get(ids[0])[0];
        double hi = cells.get(ids[ids.length - 1])[1];
        double dlo = WalletOmega.dlo(d), dhi = WalletOmega.dhi(d);
        String range;
        if (lo == hi) range = "exactly " + formatNumber(lo, unit);
        else if (lo == dlo && hi == dhi) range = "any value";
        else if (hi == dhi) range = formatNumber(lo, unit) + " or more";
        else if (lo == dlo) range = "up to " + formatNumber(hi, unit);
        else range = formatNumber(lo, unit) + " – " + formatNumber(hi, unit);
        String ex = JsVal.isNumber(actionValue) && Wallet.isFinite(actionValue) ? " (this action: " + formatNumber(Wallet.nv(actionValue), unit) + ")" : "";
        return range + ex;
    }

    private static String catValueText(Map<String, Object> d, int i) {
        Map<String, Object> v = WalletOmega.value(d, i);
        if ("exact".equals(v.get("kind"))) return "\"" + cleanText((String) v.get("value"), 64) + "\"";
        if ("prefix".equals(v.get("kind"))) return "anything starting with \"" + cleanText((String) v.get("value"), 64) + "\"";
        return "a value not named in your request";
    }

    private static String catFact(Map<String, Object> d, int[] ids, Object actionValue) {
        List<String> parts = new ArrayList<>();
        for (int i : ids) parts.add(catValueText(d, i));
        String set = parts.size() == 1 ? parts.get(0) : String.join(", ", parts.subList(0, Math.max(0, parts.size() - 1))) + " or " + (parts.isEmpty() ? "undefined" : parts.get(parts.size() - 1)); // an empty value set reaches `undefined`
        if (!(actionValue instanceof String)) return set;
        boolean named = false;
        for (Object v : WalletOmega.values(d)) if ("exact".equals(((Map<?, ?>) v).get("kind")) && actionValue.equals(((Map<?, ?>) v).get("value"))) named = true;
        String av = (String) actionValue;
        return set + " (this action: " + (named ? "\"" + cleanText(av, 64) + "\"" : "a value ending in \"" + last4(av) + "\"") + ")";
    }

    private static String bannerFor(String path, List<String> levels) {
        String w = Wallet.worstProvenance(levels);
        String label = dimLabel(path);
        if (w.equals("web")) return "This " + label + " was suggested by content on a web page, not by you.";
        if (w.equals("tool")) return "This " + label + " came from a tool result, not from you.";
        if (w.equals("agent")) return "This " + label + " was chosen by your agent, not taken from your request or from the site.";
        return null;
    }

    private static List<String> provLevels(Map<String, Object> d, int[] ids) {
        List<String> out = new ArrayList<>();
        for (int i : ids) for (String p : WalletBox.catLabel(d, i).split("[|,]", -1)) out.add(p);
        return out;
    }

    // ---- render ---------------------------------------------------------------------------------------------------------

    private static Map<String, Object> typedTarget(Map<String, Object> vs, Map<String, Object> action, Object units) {
        if (action == null) return null;
        Object values = action.get("values");
        List<Map<String, Object>> dims = new ArrayList<>();
        for (int k = 0; k < WalletOmega.dims(vs).size(); k++) {
            Map<String, Object> d = WalletOmega.dim(vs, k);
            if (!isProvPath((String) d.get("path"))) dims.add(d);
        }
        Map<String, Object> pick = null, money = null;
        for (Map<String, Object> d : dims) {
            if ("num".equals(d.get("kind")) && JsVal.isNumber(JsVal.get(values, (String) d.get("path")))) {
                if (pick == null) pick = d;
                if (money == null && isMoney(JsVal.get(units, (String) d.get("path")))) money = d;
            }
        }
        if (money != null) pick = money;
        if (pick != null) return Wallet.obj("path", pick.get("path"), "mode", "number", "prompt", "To allow it, type the " + dimLabel((String) pick.get("path")) + " of this action shown above.");
        for (Map<String, Object> d : dims) {
            Object v = JsVal.get(values, (String) d.get("path"));
            if ("cat".equals(d.get("kind")) && v instanceof String && last4((String) v).length() == 4)
                return Wallet.obj("path", d.get("path"), "mode", "last4", "prompt", "To allow it, type the last 4 letters or digits of the " + dimLabel((String) d.get("path")) + ".");
        }
        return null;
    }

    private static List<Object> answers(String label) {
        List<Object> l = new ArrayList<>();
        l.add(Wallet.obj("id", "no", "label", "No"));
        l.add(Wallet.obj("id", "partly", "label", "Partly…"));
        l.add(Wallet.obj("id", "yes", "label", label));
        return l;
    }

    private static List<Object> answersFor(Object friction) {
        if ("tap".equals(friction)) return answers("Yes");
        if ("hold".equals(friction)) return answers("Press and hold to allow");
        if ("typed".equals(friction)) return answers("Yes, type the value to confirm");
        if ("device".equals(friction)) return answers("Yes, confirm with your security key");
        return null;
    }

    private static String revText(Object rev) {
        if ("reversible".equals(rev)) return "that can be undone";
        if ("rate_limited".equals(rev)) return "that is rate-limited";
        if ("irreversible".equals(rev)) return "that cannot be undone";
        return "undefined";
    }

    private static Map<String, Object> refuse(String reason) { return Wallet.obj("ok", false, "reason", reason); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> renderCard(Map<String, Object> input) { return renderCard(input, Catalog.DEFAULT); }

    /**
     * Render the card of a question: {ok:true, card} or {ok:false, reason}. {@code input} members: omega, verb, coords, site
     * {origin, name}, statementText?, reversibility?, units?, action? {verb, values}, friction, kind, reason?, locale?.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> renderCard(Map<String, Object> input, Catalog catalog) {
        Object locale = Wallet.defined(input, "locale") && input.get("locale") != null ? input.get("locale") : "en";
        if (!"en".equals(locale)) return refuse("unsupported locale " + (input.get("locale") == null ? "null" : String.valueOf(input.get("locale"))));
        Object kind = input.get("kind");
        Object reason = input.get("reason");
        boolean hasReason = Wallet.defined(input, "reason");
        if ("clarification".equals(kind) && !hasReason) return refuse("a clarification card needs a reason");
        if (hasReason && !(reason instanceof String && CLARIFY_REASONS.contains(reason))) return refuse("unknown clarification reason");
        Map<String, Object> omega = (Map<String, Object>) input.get("omega");
        String verb = (String) input.get("verb");
        if (verb == null && !input.containsKey("verb") && omega != null) return refuse("verb undefined is not in the wallet's outcome space");
        WalletBox.BoxResult r = WalletBox.resolveCoords(omega, verb, (Map<String, Object>) input.get("coords"));
        if (!r.ok) return refuse(r.reason);
        Map<String, Object> vs = r.vs;
        int[][] box = r.box;
        Object actionO = input.get("action");
        Map<String, Object> action = actionO instanceof Map ? (Map<String, Object>) actionO : null;
        if (JsVal.truthy(actionO) && (action == null || !verb.equals(action.get("verb")))) return refuse("the action is for another verb");
        Map<String, Object> site = (Map<String, Object>) input.get("site");
        String siteName = cleanText((String) site.get("name"), 64);
        if (siteName.isEmpty()) siteName = cleanText((String) site.get("origin"), 64);
        String said = Wallet.defined(input, "statementText") ? cleanText((String) input.get("statementText"), 280) : "";
        String header;
        if ("clarification".equals(kind)) header = !said.isEmpty() ? "Your agent needs a decision for your request \"" + said + "\"" : "Your agent needs a decision";
        else header = !said.isEmpty() ? siteName + " asks on behalf of your request \"" + said + "\"" : siteName + " asks for your confirmation";
        Catalog.Spec spec = catalog.get(verb);
        String what;
        if (spec != null) {
            String desc = spec.description.endsWith(".") ? spec.description.substring(0, spec.description.length() - 1) : spec.description;
            what = desc.isEmpty() ? desc : desc.substring(0, 1).toLowerCase(java.util.Locale.ROOT) + desc.substring(1);
        } else what = "the action \"" + cleanText(verb, 64) + "\" on " + siteName;
        Object rev = input.get("reversibility") != null ? input.get("reversibility") : vs.get("reversibility");
        String sentence = "Allow " + what + ", " + revText(rev) + ", with:";
        Object units = input.get("units");
        List<Object> facts = new ArrayList<>();
        List<Object> banners = new ArrayList<>();
        List<Object> partial = new ArrayList<>();
        Object avs = action == null ? null : action.get("values");
        for (int k = 0; k < WalletOmega.dims(vs).size(); k++) {
            Map<String, Object> d = WalletOmega.dim(vs, k);
            int[] ids = box[k];
            String path = (String) d.get("path");
            if (isProvPath(path)) {
                if (!"cat".equals(d.get("kind"))) continue;
                String b = bannerFor(path.substring("env.prov.".length()), provLevels(d, ids));
                if (b != null) banners.add(b);
                continue;
            }
            Object av = JsVal.get(avs, path);
            if ("num".equals(d.get("kind"))) {
                facts.add(Wallet.obj("key", path, "label", dimLabel(path), "text", numFact(d, ids, JsVal.get(units, path), av)));
                List<double[]> cells = WalletOmega.numCells(d);
                partial.add(Wallet.obj("path", path, "kind", "num", "lo", cells.get(ids[0])[0], "hi", cells.get(ids[ids.length - 1])[1]));
            } else {
                facts.add(Wallet.obj("key", path, "label", dimLabel(path), "text", catFact(d, ids, av)));
                List<Object> options = new ArrayList<>();
                for (int i : ids) if ("exact".equals(WalletOmega.value(d, i).get("kind"))) options.add(WalletOmega.value(d, i).get("value"));
                if (options.size() > 1) partial.add(Wallet.obj("path", path, "kind", "cat", "options", options));
            }
        }
        Object friction = input.get("friction");
        Map<String, Object> typed = Wallet.frictionRank(friction) >= Wallet.frictionRank("typed") ? typedTarget(vs, action, units) : null;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", JsVal.n(2));
        body.put("kind", kind);
        body.put("verb", verb);
        body.put("coords", Wallet.plain(input.get("coords")));
        body.put("locale", "en");
        body.put("site", Wallet.obj("origin", cleanText((String) site.get("origin"), 256), "name", siteName));
        body.put("header", header);
        if (hasReason) body.put("reason_label", REASON_LABELS.get(reason));
        body.put("sentence", sentence);
        body.put("facts", facts);
        body.put("banners", banners);
        body.put("friction", friction);
        List<Object> ans = answersFor(friction);
        if (ans != null) body.put("answers", ans);
        if (typed != null) body.put("typed", typed);
        body.put("partial", partial);
        Map<String, Object> card = new LinkedHashMap<>(body);
        card.put("rendered_digest", cardDigest(body));
        return Wallet.obj("ok", true, "card", card);
    }

    /** The content address of a card body (everything but rendered_digest). */
    public static String cardDigest(Map<String, Object> body) { return Pca.hashCanonical(Wallet.obj("d", CARD_DOMAIN, "c", Wallet.plain(body))); }

    /** Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed. */
    public static boolean cardDigestMatches(Map<String, Object> card) {
        Map<String, Object> body = new LinkedHashMap<>(card);
        Object d = body.remove("rendered_digest");
        return cardDigest(body).equals(d);
    }

    /** The plain text of a card, line by line (what a screen reader or a text channel shows). */
    @SuppressWarnings("unchecked")
    public static String cardText(Map<String, Object> card) {
        List<String> lines = new ArrayList<>();
        lines.add((String) card.get("header"));
        if (JsVal.truthy(card.get("reason_label"))) lines.add((String) card.get("reason_label"));
        lines.add((String) card.get("sentence"));
        for (Object f : (List<Object>) card.get("facts")) lines.add("- " + ((Map<String, Object>) f).get("label") + ": " + ((Map<String, Object>) f).get("text"));
        for (Object b : (List<Object>) card.get("banners")) lines.add((String) b);
        if (card.get("typed") != null) lines.add((String) ((Map<String, Object>) card.get("typed")).get("prompt"));
        List<String> as = new ArrayList<>();
        for (Object a : (List<Object>) card.get("answers")) as.add("[" + ((Map<String, Object>) a).get("label") + "]");
        lines.add(String.join(" ", as));
        return String.join("\n", lines);
    }

    // ---- responses ------------------------------------------------------------------------------------------------------

    private static boolean inRange(Object x, double lo, double hi) {
        double v = Wallet.nv(x);
        return Wallet.isSafeInteger(x) && !JsVal.isNegZero(x) && v >= lo && v <= hi;
    }

    /** Validate a "Partly..." answer against the card: a structured restriction of the shown ranges and values only. */
    @SuppressWarnings("unchecked")
    public static String partialError(Map<String, Object> card, Map<String, Object> p) {
        Map<String, Object> slot = null;
        for (Object s : (List<Object>) card.get("partial")) if (((Map<String, Object>) s).get("path").equals(p.get("path"))) { slot = (Map<String, Object>) s; break; }
        if (slot == null) return "the card has no field " + p.get("path");
        if ("num".equals(slot.get("kind"))) {
            double lo = Wallet.nv(slot.get("lo")), hi = Wallet.nv(slot.get("hi"));
            if (p.containsKey("upTo")) return inRange(p.get("upTo"), lo, hi) && Wallet.nv(p.get("upTo")) < hi ? null : "upTo must be an integer in [" + jsNum(lo) + ", " + jsNum(hi - 1) + "]";
            if (p.containsKey("from")) return inRange(p.get("from"), lo, hi) && Wallet.nv(p.get("from")) > lo ? null : "from must be an integer in [" + jsNum(lo + 1) + ", " + jsNum(hi) + "]";
            if (p.containsKey("except")) {
                List<Object> ex = (List<Object>) p.get("except");
                boolean ok = !ex.isEmpty();
                for (Object x : ex) if (!inRange(x, lo, hi)) ok = false;
                return ok ? null : "except values must be integers in [" + jsNum(lo) + ", " + jsNum(hi) + "]";
            }
            return "a numeric partly answer needs upTo, from or except";
        }
        if (!p.containsKey("notFor")) return "a categorical partly answer needs notFor";
        LinkedHashSet<Object> vals = new LinkedHashSet<>((List<Object>) p.get("notFor"));
        List<Object> options = (List<Object>) slot.get("options");
        boolean allShown = true;
        for (Object v : vals) if (!options.contains(v)) allShown = false;
        if (vals.isEmpty() || !allShown) return "notFor must name values shown on the card";
        if (vals.size() == options.size()) return "excluding every value is a \"No\"";
        return null;
    }

    private static final Pattern TYPED_STRIP = Pattern.compile("(?:" + WS + "|[,$€£¥])");
    private static final Pattern CCY_PREFIX = Pattern.compile("^[A-Z]{3}", Pattern.CASE_INSENSITIVE);
    private static final Pattern NUM_RE = Pattern.compile("(-?)(\\d+)(?:\\.(\\d+))?");

    /** Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money). */
    public static String normalizeTyped(String input, String mode, Object unit) {
        if (mode.equals("last4")) {
            String t = NOT_ALNUM.matcher(input).replaceAll("").toUpperCase(java.util.Locale.ROOT);
            return t.length() == 4 ? t : null;
        }
        String t = TYPED_STRIP.matcher(input).replaceAll("");
        t = CCY_PREFIX.matcher(t).replaceFirst("");
        Matcher m = NUM_RE.matcher(t);
        if (!m.matches()) return null;
        int e = isMoney(unit) ? (int) exponentOf(unit) : 0;
        String frac = m.group(3) == null ? "" : m.group(3);
        if (frac.length() > e) return null;
        StringBuilder padded = new StringBuilder(frac);
        while (padded.length() < e) padded.append('0');
        BigInteger minor = new BigInteger(m.group(2)).multiply(BigInteger.TEN.pow(e)).add(frac.isEmpty() ? BigInteger.ZERO : new BigInteger(padded.toString()));
        return ("-".equals(m.group(1)) && minor.signum() != 0 ? "-" : "") + minor;
    }

    /** The normalized value the human must type for this card and action (what a site or auditor recomputes); null when none. */
    @SuppressWarnings("unchecked")
    public static String expectedTyped(Map<String, Object> card, Map<String, Object> action) {
        Object typed = card.get("typed");
        if (typed == null) return null;
        Object v = JsVal.get(action.get("values"), (String) ((Map<String, Object>) typed).get("path"));
        if ("last4".equals(((Map<String, Object>) typed).get("mode"))) return v instanceof String && last4((String) v).length() == 4 ? last4((String) v) : null;
        return JsVal.isNumber(v) && Wallet.isSafeInteger(v) && !JsVal.isNegZero(v) ? jsNum(Wallet.nv(v)) : null;
    }
}
