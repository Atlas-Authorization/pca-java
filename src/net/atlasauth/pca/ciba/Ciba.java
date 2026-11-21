package net.atlasauth.pca.ciba;

import net.atlasauth.pca.Json;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.Approval;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Pca;

/**
 * A CIBA (OpenID Connect Client-Initiated Backchannel Authentication) on-ramp for PCA's step-up: a step-up request becomes a
 * backchannel authentication request (binding message, scope, expiry, interval) with risk-adaptive gating. Mirrors the
 * TypeScript package's main module. A step-up is a JSON object with the reference's field names ({@code id}, {@code verb},
 * {@code resource}, {@code params}, {@code tier}, {@code goalCommit}, {@code goal}, {@code render}, {@code renderDigest});
 * request options use the reference's option names ({@code expiresInSec}, {@code authReqId}, {@code stepUpScope}, {@code loginHint},
 * {@code bindingMessage} = {maxChars, tokenOnly}, {@code interval}, {@code actsFor}). Every refusal throws
 * {@link IllegalArgumentException} (the reference's RangeError / TypeError). Nothing here authorises anything: the resource server's
 * verifier and the FROST cosigners remain the authority.
 *
 * <p>The payee homograph checks use the JDK's Unicode tables, so a character added to Unicode after JDK 17's version reads as
 * unassigned and is refused. {@link #asciiForm} encodes a word as the URL standard's domain-to-ASCII does (UTS 46 through ICU4J, then
 * punycode); a word the standard refuses is shown in its escaped form.
 */
public final class Ciba {
    private Ciba() {}

    static final int DEFAULT_EXPIRY_SEC = 300;
    static final int DEFAULT_INTERVAL_SEC = 5;
    static final int MIN_AUTH_REQ_ID_LEN = 22;
    static final int MAX_GOAL_CHARS = 100;
    static final int MAX_PAYEE_CHARS = 64;
    static final List<String> PAYEE_KEYS = List.of("payee", "to", "recipient", "beneficiary", "destination");
    private static final Set<String> DISPLAYED_PARAM_KEYS;
    static {
        Set<String> s = new LinkedHashSet<>(List.of("amount", "currency"));
        s.addAll(PAYEE_KEYS);
        DISPLAYED_PARAM_KEYS = s;
    }

    private static final String WS_CLASS = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    private static final Pattern FORGED_CLAUSE = Pattern.compile("because[" + WS_CLASS + "]+you[" + WS_CLASS + "]+asked", Pattern.CASE_INSENSITIVE);
    private static final Pattern AUTH_REQ_ID = Pattern.compile("[A-Za-z0-9._-]+");
    private static final Pattern IDENT = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}");
    private static final Pattern PLAIN_AMOUNT = Pattern.compile("(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?");
    private static final Pattern CURRENCY = Pattern.compile("[A-Za-z]{3}");
    private static final Pattern WS_TWO = Pattern.compile("[" + WS_CLASS + "]{2,}");

    private static IllegalArgumentException range(String m) { return new IllegalArgumentException(m); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    // ---- text helpers ----------------------------------------------------------------------------------------------------------

    private static int cpLen(String s) { return s.codePointCount(0, s.length()); }

    /**
     * Make untrusted text safe for a one-line, plain-text approval prompt: control characters, line breaks and bidi / zero-width
     * formatting characters become spaces, runs of whitespace collapse.
     */
    static String plainText(String value) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        boolean inWs = false;
        while (i < value.length()) {
            int cp = value.codePointAt(i);
            i += Character.charCount(cp);
            int t = Character.getType(cp);
            boolean space = t == Character.CONTROL || t == Character.FORMAT || cp == 0x2028 || cp == 0x2029 || CibaJs.isWs(cp);
            if (space) { if (!inWs) sb.append(' '); inWs = true; }
            else { sb.appendCodePoint(cp); inWs = false; }
        }
        return CibaJs.trim(sb.toString());
    }

    static String clip(String value, double max) {
        int n = cpLen(value);
        if (n <= max) return value;
        int keep = (int) max - 1;
        int end = value.offsetByCodePoints(0, Math.max(0, Math.min(keep, n)));
        return value.substring(0, end) + "\u2026";
    }

    private static boolean asciiPrintable(String s, boolean allowEmpty) {
        if (s.isEmpty()) return allowEmpty;
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (c < 0x20 || c > 0x7e) return false; }
        return true;
    }

    private static String identifier(Object value, String what) {
        if (!(value instanceof String) || !IDENT.matcher((String) value).matches())
            throw range("ciba: the step-up " + what + " must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message");
        if (FORGED_CLAUSE.matcher((String) value).find()) throw range("ciba: the step-up " + what + " contains an approval-explanation clause");
        return (String) value;
    }

    private static boolean undisplayable(int cp) {
        int t = Character.getType(cp);
        return t == Character.CONTROL || t == Character.FORMAT || t == Character.SURROGATE || t == Character.PRIVATE_USE || t == Character.UNASSIGNED
            || cp == 0x2028 || cp == 0x2029 || (cp >= 0xfff9 && cp <= 0xfffd);
    }

    private static boolean isMark(int cp) {
        int t = Character.getType(cp);
        return t == Character.NON_SPACING_MARK || t == Character.COMBINING_SPACING_MARK || t == Character.ENCLOSING_MARK;
    }

    private static String payeeText(Object value) {
        if (!(value instanceof String)) throw range("ciba: the payee must be a string (a nested value cannot be shown to the approver)");
        String t = Normalizer.normalize((String) value, Normalizer.Form.NFC);
        if (t.isEmpty() || !CibaJs.trim(t).equals(t) || WS_TWO.matcher(t).find()) throw range("ciba: the payee must be non-empty without leading, trailing or repeated whitespace");
        boolean bad = false;
        for (int i = 0; i < t.length(); ) { int cp = t.codePointAt(i); i += Character.charCount(cp); if (undisplayable(cp)) { bad = true; break; } }
        if (bad || t.indexOf('\r') >= 0 || t.indexOf('\n') >= 0 || t.indexOf('\t') >= 0)
            throw range("ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed");
        if (t.indexOf('"') >= 0 || t.indexOf('\\') >= 0) throw range("ciba: the payee must not contain quote or backslash characters");
        if (cpLen(t) > MAX_PAYEE_CHARS) throw range("ciba: the payee is longer than " + MAX_PAYEE_CHARS + " characters; refusing to truncate what the person approves");
        if (FORGED_CLAUSE.matcher(t).find()) throw range("ciba: the payee contains an approval-explanation clause");
        // Look-alikes: NFC already composed what can be composed, so a combining mark left is stacked or decorative; compatibility forms differ from
        // their plain look-alike under NFKC; a payee that mixes scripts is the classic homograph.
        for (int i = 0; i < t.length(); ) { int cp = t.codePointAt(i); i += Character.charCount(cp); if (isMark(cp)) throw range("ciba: the payee contains combining marks and cannot be shown unambiguously"); }
        if (!Normalizer.normalize(t, Normalizer.Form.NFKC).equals(t)) throw range("ciba: the payee contains compatibility/fullwidth characters that imitate plain ones");
        if (scriptsOf(t).size() > 1) throw range("ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike");
        return t;
    }

    /** Writing-system groups present in {@code t} (letters only; digits, punctuation and spaces are script-neutral). */
    static Set<String> scriptsOf(String t) {
        Set<String> found = new LinkedHashSet<>();
        for (int i = 0; i < t.length(); ) {
            int cp = t.codePointAt(i);
            i += Character.charCount(cp);
            if (!Character.isLetter(cp)) continue;
            String g = null;
            switch (Character.UnicodeScript.of(cp)) {
                case LATIN: g = "latin"; break;
                case CYRILLIC: g = "cyrillic"; break;
                case GREEK: g = "greek"; break;
                case ARMENIAN: g = "armenian"; break;
                case HEBREW: g = "hebrew"; break;
                case ARABIC: g = "arabic"; break;
                case HAN: case HIRAGANA: case KATAKANA: case HANGUL: case BOPOMOFO: g = "cjk"; break;
                case DEVANAGARI: case BENGALI: case TAMIL: case THAI: case GEORGIAN: g = "indic-thai"; break;
                default: break;
            }
            found.add(g != null ? g : "other:" + new String(Character.toChars(cp)));
        }
        return found;
    }

    // ---- ASCII form of a payee (UTS 46) ---------------------------------------------------------------------------------------

    private static int hex(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

    private static String percentDecode(String h) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < h.length(); ) {
            char c = h.charAt(i);
            if (c == '%' && i + 2 < h.length() + 0 && hex(h.charAt(i + 1)) >= 0 && hex(h.charAt(i + 2)) >= 0) {
                out.write(hex(h.charAt(i + 1)) * 16 + hex(h.charAt(i + 2)));
                i += 3;
                continue;
            }
            int cp = h.codePointAt(i);
            i += Character.charCount(cp);
            byte[] b = Json.utf8(new String(Character.toChars(cp)));
            out.write(b, 0, b.length);
        }
        return new String(out.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * {@code url.domainToASCII} (the host of {@code ws://<word>}): the word ends at the first {@code / ? # \}, a valid {@code %XX} is decoded, then UTS 46
     * to ASCII (mapping, validity, bidi, joiners, punycode) through ICU4J as the URL standard specifies; a forbidden host character after mapping or a numeric
     * last label (an IPv4 form) is refused; empty when the host cannot be encoded.
     */
    public static String domainToAscii(String w) {
        int cut = w.length();
        for (int i = 0; i < w.length(); i++) { char c = w.charAt(i); if (c == '/' || c == '?' || c == '#' || c == '\\') { cut = i; break; } }
        String host = w.substring(0, cut);
        if (host.isEmpty()) return "";
        String decoded = percentDecode(host);
        String ascii = net.atlasauth.pca.oauth.HostIdna.needsProcessing(decoded) ? net.atlasauth.pca.oauth.HostIdna.toAscii(decoded) : decoded.toLowerCase(Locale.ROOT);
        if (ascii == null || ascii.isEmpty()) return "";
        for (int i = 0; i < ascii.length(); i++) {
            char c = ascii.charAt(i);
            if (c <= 0x20 || c == 0x7f || "#%/:<>?@[\\]^|".indexOf(c) >= 0) return "";
        }
        String[] labels = ascii.split("\\.", -1);
        int last = labels.length - 1;
        if (last > 0 && labels[last].isEmpty()) last--;
        String l = labels[last];
        if (l.matches("[0-9]+") || l.matches("0[xX][0-9a-fA-F]*")) return "";
        return ascii;
    }

    /** Plain-ASCII rendering of a payee: itself when ASCII, else the punycode of each word (or braced code point escapes when IDNA refuses). */
    public static String asciiForm(String payee) {
        if (asciiPrintable(payee, true)) return payee;
        String[] words = payee.split(" ", -1);
        List<String> out = new ArrayList<>();
        for (String w : words) {
            if (asciiPrintable(w, true)) { out.add(w); continue; }
            String a = domainToAscii(w);
            if (!a.isEmpty()) { out.add(a); continue; }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < w.length(); ) {
                int cp = w.codePointAt(i);
                i += Character.charCount(cp);
                if (cp > 0x7e) sb.append("\\u{").append(Integer.toHexString(cp)).append('}'); else sb.appendCodePoint(cp);
            }
            out.add(sb.toString());
        }
        return String.join(" ", out);
    }

    // ---- the canonical action ---------------------------------------------------------------------------------------------------

    private static boolean present(Object v) { return v != null; }

    /**
     * Build the canonical action from a step-up: {@code {verb, [amount, currency,] [payee,] resource}}. Fails loud: unknown params keys,
     * a nested or malformed amount, a missing currency or payee next to an amount, two different payee fields, and non-identifier
     * verb / resource all throw.
     */
    public static Map<String, Object> cibaActionFromStepUp(Map<String, Object> stepUp) {
        Object po = stepUp.get("params");
        if (po == null) po = new LinkedHashMap<String, Object>();
        if (!(po instanceof Map)) throw range("ciba: step-up params must be an object");
        Map<String, Object> params = map(po);
        List<String> unknown = new ArrayList<>();
        for (String k : params.keySet()) if (!DISPLAYED_PARAM_KEYS.contains(k)) unknown.add(k);
        if (!unknown.isEmpty())
            throw range("ciba: step-up params field(s) " + String.join(", ", unknown) + " are not displayed in the approval message (displayable: amount, currency, "
                + String.join("/", PAYEE_KEYS) + "); refusing so the person never approves a hidden field");
        Map<String, Object> action = Issue.obj("verb", identifier(stepUp.get("verb"), "verb"), "resource", identifier(stepUp.get("resource"), "resource"));
        List<String> payeeKeys = new ArrayList<>();
        for (String k : PAYEE_KEYS) if (present(params.get(k))) payeeKeys.add(k);
        if (payeeKeys.size() > 1) throw range("ciba: more than one payee field (" + String.join(", ", payeeKeys) + ") in params; the approver would see only one");
        if (present(params.get("amount"))) {
            Object amt = params.get("amount");
            Double d = amt instanceof Boolean ? null : CibaJs.num(amt);
            String text = d != null && !Double.isNaN(d) && !Double.isInfinite(d) ? CibaJs.jsNumber(d) : amt instanceof String ? (String) amt : "";
            if (!PLAIN_AMOUNT.matcher(text).matches()) throw range("ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)");
            Object cur = params.get("currency");
            if (!(cur instanceof String) || !CURRENCY.matcher((String) cur).matches()) throw range("ciba: the binding message needs a 3-letter currency code next to the amount");
            if (payeeKeys.isEmpty()) throw range("ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it");
            action.put("amount", text);
            action.put("currency", ((String) cur).toUpperCase(Locale.ROOT));
        } else if (present(params.get("currency"))) {
            throw range("ciba: a currency without an amount cannot be displayed");
        }
        if (payeeKeys.size() == 1) {
            Map<String, Object> out = Issue.obj("verb", action.get("verb"));
            if (action.containsKey("amount")) { out.put("amount", action.get("amount")); out.put("currency", action.get("currency")); }
            out.put("payee", payeeText(params.get(payeeKeys.get(0))));
            out.put("resource", action.get("resource"));
            return out;
        }
        return action;
    }

    // ---- the binding message ----------------------------------------------------------------------------------------------------

    private static String bindingMessage(Map<String, Object> stepUp, String actsFor, Double maxChars) {
        Map<String, Object> a = cibaActionFromStepUp(stepUp);
        StringBuilder head = new StringBuilder("Approve ").append(a.get("verb"));
        if (a.containsKey("amount")) head.append(' ').append(a.get("amount")).append(' ').append(a.get("currency"));
        if (a.containsKey("payee")) {
            String p = (String) a.get("payee");
            head.append(" to \"").append(p).append('"');
            if (!asciiPrintable(p, true)) head.append(" [non-ASCII name; ASCII form: ").append(asciiForm(p)).append(']');
        }
        head.append(" on ").append(a.get("resource"));
        double limit = maxChars == null ? Double.POSITIVE_INFINITY : maxChars;
        String h = head.toString();
        if (cpLen(h) > limit)
            throw range("ciba: the binding message needs " + cpLen(h) + " characters but bindingMessage.maxChars is " + CibaJs.jsNumber(maxChars) + "; refusing to truncate what the person approves");
        String plainGoal = "";
        if (stepUp.containsKey("goal")) {
            if (!(stepUp.get("goal") instanceof String)) throw range("ciba: the step-up goal must be a string");
            plainGoal = plainText((String) stepUp.get("goal")).replace('\'', '\u2032').replace('\u2018', '\u2032').replace('\u2019', '\u2032');
        }
        String goalText;
        if (!plainGoal.isEmpty()) goalText = clip(plainGoal, MAX_GOAL_CHARS);
        else {
            Object gc = stepUp.get("goalCommit");
            if (gc == null) throw range("ciba: the step-up goalCommit is required");
            String s = gc instanceof String ? (String) gc : "";
            goalText = !s.isEmpty() ? "goal " + s.substring(0, Math.min(10, s.length())) + "\u2026" : null;
        }
        if (goalText == null) return h;
        String prefix = " \u2014 because you asked " + actsFor + " to '";
        double room = limit - cpLen(h + prefix) - 1;
        if (room >= cpLen(goalText)) return h + prefix + goalText + "'";
        if (room >= 8) return h + prefix + clip(goalText, room) + "'";
        return h;
    }

    private static String tokenise(String value) {
        return value.replaceAll("[^A-Za-z0-9._-]+", "-").replaceAll("-{2,}", "-").replaceAll("^[-.]+|[-.]+$", "");
    }

    private static String compactBindingMessage(Map<String, Object> stepUp, double maxChars) {
        Map<String, Object> a = cibaActionFromStepUp(stepUp);
        if (a.containsKey("payee") && !asciiPrintable((String) a.get("payee"), false))
            throw range("ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)");
        List<String> parts = new ArrayList<>();
        parts.add("Approve");
        parts.add((String) a.get("verb"));
        if (a.containsKey("amount")) { parts.add((String) a.get("amount")); parts.add((String) a.get("currency")); }
        if (a.containsKey("payee")) { parts.add("to"); parts.add((String) a.get("payee")); }
        parts.add((String) a.get("resource"));
        List<String> toks = new ArrayList<>();
        for (String p : parts) toks.add(tokenise(p));
        for (String p : toks) if (p.isEmpty()) throw range("ciba: tokenOnly binding message cannot represent the verb, payee or resource");
        String out = String.join("-", toks);
        if (out.length() > maxChars)
            throw range("ciba: the binding message needs " + out.length() + " characters but bindingMessage.maxChars is " + CibaJs.jsNumber(maxChars) + "; refusing to truncate what the person approves");
        return out;
    }

    // ---- the request ------------------------------------------------------------------------------------------------------------

    private static Object opt(Map<String, Object> o, String k) { return o != null && o.containsKey(k) ? o.get(k) : CibaJs.ABSENT; }

    /**
     * Map a PCA step-up to a CIBA auth request: {@code {auth_req_id, binding_message, scope, requested_expiry, interval, [login_hint,]
     * stepUpId, tier, [authorization_details, render_digest]}}. Pure: derives a stable {@code auth_req_id} from the step-up id unless
     * {@code opts.authReqId} is given, renders the binding message, and carries the scope, expiry and poll interval.
     */
    public static Map<String, Object> toCibaAuthRequest(Map<String, Object> stepUp, Map<String, Object> opts) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        String actsFor = "your agent";
        if (o.containsKey("actsFor")) {
            if (!(o.get("actsFor") instanceof String)) throw range("ciba: actsFor must be a string");
            String pt = plainText((String) o.get("actsFor"));
            if (!pt.isEmpty()) actsFor = clip(pt, 40);
        }
        Object requestedExpiry = o.containsKey("expiresInSec") ? o.get("expiresInSec") : new net.atlasauth.pca.Json.Num(Integer.toString(DEFAULT_EXPIRY_SEC));
        if (!CibaJs.isSafeInteger(requestedExpiry) || CibaJs.num(requestedExpiry) <= 0)
            throw range("ciba: requested_expiry must be a positive integer number of seconds, got " + CibaJs.str(requestedExpiry));
        String stepUpScope = "urn:atlas:pca:stepup:" + CibaJs.str(CibaJs.get(stepUp, "verb"));
        for (int i = 0; i < stepUpScope.length(); i++) {
            char c = stepUpScope.charAt(i);
            if (!(c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e))) throw range("ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)");
        }
        String scope = Boolean.FALSE.equals(o.get("stepUpScope")) ? "openid" : "openid " + stepUpScope;
        Object interval = o.containsKey("interval") ? o.get("interval") : new net.atlasauth.pca.Json.Num(Integer.toString(DEFAULT_INTERVAL_SEC));
        if (!CibaJs.isSafeInteger(interval) || CibaJs.num(interval) <= 0)
            throw range("ciba: interval must be a positive integer number of seconds, got " + CibaJs.str(interval));
        Object idO = o.get("authReqId");
        if (idO == null && !stepUp.containsKey("id")) throw range("ciba: the step-up has no id to derive the auth_req_id from");
        // the reference tests String(id) against the pattern and reads .length, which a non-string does not have
        Object authReqId = idO != null ? idO : Pca.hashCanonical(Issue.obj("d", "atlas-pca/ciba/auth_req_id/v1", "stepUp", stepUp.get("id")));
        int idLen = authReqId instanceof String ? ((String) authReqId).length() : authReqId instanceof List ? ((List<?>) authReqId).size() : -1;
        if (!AUTH_REQ_ID.matcher(CibaJs.str(authReqId)).matches() || (idLen >= 0 && (idLen < MIN_AUTH_REQ_ID_LEN || idLen > 1024)))
            throw range("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)");
        Object bmO = o.get("bindingMessage");
        Map<String, Object> bm = bmO instanceof Map ? map(bmO) : null;
        boolean hasMax = bm != null && bm.containsKey("maxChars");
        Object bmMax = hasMax ? bm.get("maxChars") : null;
        if (hasMax && (!CibaJs.isSafeInteger(bmMax) || CibaJs.num(bmMax) < 1)) throw range("ciba: bindingMessage.maxChars must be a positive integer");
        double maxChars = hasMax && bmMax != null ? CibaJs.num(bmMax) : 50;
        String words = null;
        Object render = stepUp.get("render"), renderDigest = stepUp.get("renderDigest");
        if (stepUp.containsKey("render") || stepUp.containsKey("renderDigest")) {
            if (!stepUp.containsKey("render") || !stepUp.containsKey("renderDigest") || !Approval.renderDigest(render).equals(renderDigest))
                throw range("ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else");
            words = Approval.bindingWords(renderDigest);
        }
        int reserve = words == null ? 0 : words.length() + 14;
        boolean tokenOnly = bm != null && Boolean.TRUE.equals(bm.get("tokenOnly"));
        String bindingMessage = tokenOnly ? compactBindingMessage(stepUp, maxChars - reserve)
            : bindingMessage(stepUp, actsFor, hasMax ? Double.valueOf(CibaJs.num(bmMax) - reserve) : null);
        if (words != null) bindingMessage = tokenOnly ? bindingMessage + "-match-" + words : bindingMessage + " [match code " + words + "]";
        Map<String, Object> out = Issue.obj("auth_req_id", authReqId, "binding_message", bindingMessage, "scope", scope, "requested_expiry", requestedExpiry, "interval", interval);
        if (o.containsKey("loginHint")) out.put("login_hint", o.get("loginHint"));
        if (stepUp.containsKey("id")) out.put("stepUpId", stepUp.get("id")); // an undefined member is not serialised
        if (stepUp.containsKey("tier")) out.put("tier", stepUp.get("tier"));
        if (stepUp.containsKey("render") && stepUp.containsKey("renderDigest")) {
            List<Object> details = new ArrayList<>();
            details.add(Issue.obj("type", "pca_approval", "render", render, "render_digest", renderDigest));
            out.put("authorization_details", details);
            out.put("render_digest", renderDigest);
        }
        return out;
    }

    // ---- gating and the hand-off to the cosign ----------------------------------------------------------------------------------

    /** The gate: does this review need a CIBA human-approval round-trip? Only a tier-3 step-up does (tier-2 is the guardian's auto-cosign). */
    public static boolean requiresCiba(Object review) {
        if (review == null) throw new IllegalArgumentException("ciba: review is null");
        if (!"step_up".equals(CibaJs.member(review, "kind"))) return false;
        Object req = CibaJs.member(review, "request");
        if (req == null) throw new IllegalArgumentException("ciba: the step_up review has no request");
        Double t = CibaJs.num(CibaJs.member(req, "tier"));
        return t != null && t == 3.0;
    }

    private static double nz(Object x) {
        Double d = CibaJs.num(x);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d > 0 ? d : 0;
    }

    /**
     * Fold a settled CIBA decision into PCA's trust budget {@code {B, tau, asOf?}}: on {@code approve}, recharge (partial rho per cosign, or
     * full with {@code opts.full}); on anything else the budget is unchanged. Returns {@code {budget, cosigned}}. This is the BUDGET-level effect only:
     * the cryptographic cosign that authorises a tier-3 action is a FROST threshold signature verified by the resource server.
     */
    public static Map<String, Object> cibaDecisionToCosign(Object decision, Map<String, Object> budget, Map<String, Object> policy, Object now, Map<String, Object> opts) {
        if (!"approve".equals(decision)) return Issue.obj("budget", budget, "cosigned", false);
        boolean full = opts != null && CibaJs.truthy(opts.get("full"));
        double bMax = nz(policy.get("bMax"));
        double b = full ? bMax : Math.min(bMax, CibaJs.num(budget.get("B")) + nz(policy.get("rho")));
        return Issue.obj("budget", Issue.obj("B", b, "tau", now, "asOf", now), "cosigned", true);
    }
}
