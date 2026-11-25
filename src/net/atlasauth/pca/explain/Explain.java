package net.atlasauth.pca.explain;

import static net.atlasauth.pca.explain.ExplainJs.UNDEF;
import static net.atlasauth.pca.explain.ExplainJs.get;
import static net.atlasauth.pca.explain.ExplainJs.nn;
import static net.atlasauth.pca.explain.ExplainJs.obj;
import static net.atlasauth.pca.explain.ExplainJs.opt;
import static net.atlasauth.pca.explain.ExplainJs.put;
import static net.atlasauth.pca.explain.ExplainJs.rd;
import static net.atlasauth.pca.explain.ExplainJs.str;
import static net.atlasauth.pca.explain.ExplainJs.truthy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Caveats;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Predicates;

/**
 * Make PCA decisions self-explaining: the verifier's per-check result, the Policy VM decision and a delegation chain become
 * precise, human-readable explanations. Pure and read-only; a malformed input degrades to a best-effort explanation.
 * Explanations are JSON trees (Maps) with the members of the TypeScript explanation classes; the {@code *ToText} functions
 * render them. Shortcuts: statuses/reasons/caveat lists are expected to be arrays of scalars; a null envelope counts as absent.
 */
public final class Explain {
    private Explain() {}

    public static final int MAX_TEXT = 400;
    public static final long PCACTN_VERSION = 2;
    public static final long PCACTN_MAX_LIFETIME_MS = 3_600_000L;
    public static final long PCACTN_MAX_SKEW_MS = 60_000L;

    public static final List<String> VERIFY_CHECK_ORDER = List.of(
        "wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format");

    private static final Map<String, String> CHECK_TITLE = new LinkedHashMap<>();
    static {
        String[][] t = {
            {"wire", "wire format"}, {"version", "version"}, {"audience", "audience binding"}, {"validity", "freshness window"},
            {"cap_chain", "capability chain"}, {"grant_ref_bound", "grant reference binding"}, {"plan_inclusion", "plan inclusion"},
            {"leaf_signature", "leaf signature"}, {"counter_format", "counter format"}, {"counter", "counter format"}, {"replay", "replay"},
            {"plan_root_authorized", "plan-root authorization"}, {"taint_gate", "taint gate"}, {"attestation", "agent attestation"},
            {"threshold", "threshold signature"}, {"revocation", "revocation"}, {"zk_compliance", "zk compliance"}, {"bond", "bond"},
            {"malformed", "structure"}};
        for (String[] e : t) CHECK_TITLE.put(e[0], e[1]);
    }

    // ---- cleanText -------------------------------------------------------------------------------------------------------------

    private static final String W = "A-Za-z0-9_";
    private static final String NB = "(?<![" + W + "])"; // JavaScript \b before a word character
    private static final Pattern RE_JWT = Pattern.compile(NB + "eyJ[" + W + "-]{5,}\\.[" + W + "-]{5,}\\.[" + W + "-]*");
    private static final Pattern RE_BEARER = Pattern.compile(NB + "(Bearer|Basic|Token)[" + ExplainJs.WS + "]+[" + W + ".~+/=-]{6,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern RE_USERINFO = Pattern.compile("([a-z][a-z0-9+.-]*://)[^" + ExplainJs.WS + "/@]*:[^" + ExplainJs.WS + "/@]*@", Pattern.CASE_INSENSITIVE);
    private static final Pattern RE_PAIR = Pattern.compile(NB + "((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|authorization|auth)[\"']?["
        + ExplainJs.WS + "]*[:=][" + ExplainJs.WS + "]*)(\"[^\"]*\"|'[^']*'|[^" + ExplainJs.WS + "\"'&,;]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern RE_RUN = Pattern.compile("[" + W + "-]{40,}");

    /**
     * Remove what looks like a credential from text built out of untrusted fields (JWTs, bearer credentials, URL userinfo,
     * {@code token=} style pairs, long unbroken token runs); output is cut to 400 characters. A net, not a proof.
     */
    public static String cleanText(Object text) {
        String t = str(text);
        t = RE_JWT.matcher(t).replaceAll("[redacted]");
        t = RE_BEARER.matcher(t).replaceAll("$1 [redacted]");
        t = RE_USERINFO.matcher(t).replaceAll("$1[redacted]@");
        t = RE_PAIR.matcher(t).replaceAll("$1[redacted]");
        t = RE_RUN.matcher(t).replaceAll("[redacted]");
        return t.length() > MAX_TEXT ? t.substring(0, MAX_TEXT) + "..." : t;
    }

    // ---- shared helpers --------------------------------------------------------------------------------------------------------

    private static String s(Object v) { return str(v); }

    private static String shorten(Object key) { return shorten(key, 10); }

    private static String shorten(Object key, int n) {
        if (!(key instanceof String) || ((String) key).isEmpty()) return "<none>";
        String k = (String) key;
        return k.length() <= n + 1 ? k : k.substring(0, n) + "…";
    }

    /** Compact number: integers stay integers, fractions round to 4 dp. Anything else prints as String(x). */
    static String num(Object x) {
        Double d = x instanceof Double ? (Double) x : ExplainJs.numOf(x);
        if (d == null || d.isNaN() || d.isInfinite()) return str(x);
        if (d == Math.rint(d)) return ExplainJs.numString(d);
        return ExplainJs.numString(ExplainJs.round(d * 1e4) / 1e4);
    }

    private static String valueSummary(Map<String, Object> rest) {
        List<String> parts = new ArrayList<>();
        List<String> ks = ExplainJs.keys(rest);
        for (String k : ks.subList(0, Math.min(6, ks.size()))) {
            Object v = rest.get(k);
            parts.add(k + "=" + (v instanceof Map || v instanceof List ? ExplainJs.stringify(v) : num(v)));
        }
        return String.join(", ", parts);
    }

    private static String typeOf(Object cv) {
        Object t = opt(cv, "type");
        return t instanceof String ? (String) t : "<malformed>";
    }

    /** The caveat's non-{@code type} members (insertion order, array-index keys first). */
    private static Map<String, Object> caveatRest(Object cv) {
        Map<String, Object> rest = obj();
        if (cv instanceof Map || cv instanceof List) {
            for (String k : ExplainJs.keys(cv)) if (!k.equals("type")) rest.put(k, get(cv, k));
        }
        return rest;
    }

    private static String condToText(Object c, int depth) {
        if (!(c instanceof Map || c instanceof List)) return "<malformed>";
        if (depth > 6) return "…";
        if (c instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) c;
            if (m.containsKey("all_of") && m.get("all_of") instanceof List) return "(" + joinConds((List<?>) m.get("all_of"), " AND ", depth) + ")";
            if (m.containsKey("any_of") && m.get("any_of") instanceof List) return "(" + joinConds((List<?>) m.get("any_of"), " OR ", depth) + ")";
            if (m.containsKey("not")) return "NOT " + condToText(m.get("not"), depth + 1);
        }
        Object ref = get(c, "ref");
        String operand = ref != UNDEF ? "→" + s(ref) : c instanceof Map && ((Map<?, ?>) c).containsKey("value") ? num(get(c, "value")) : "";
        return ExplainJs.jsTrim(s(get(c, "field")) + " " + s(get(c, "op")) + " " + operand);
    }

    private static String joinConds(List<?> l, String sep, int depth) {
        List<String> out = new ArrayList<>();
        for (Object x : l) out.add(condToText(x, depth + 1));
        return String.join(sep, out);
    }

    private static String whereSummary(Object where) {
        if (!(where instanceof List) || ((List<?>) where).isEmpty()) return "any (no where-bound)";
        List<String> out = new ArrayList<>();
        for (Object c : (List<?>) where) out.add(condToText(c, 0));
        return String.join(" AND ", out);
    }

    private static String padEnd(String s, int n) {
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < n) sb.append(' ');
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Map<String, Object> mapOrEmpty(Object o) { return o instanceof Map ? m(o) : new LinkedHashMap<>(); }

    // =============================================================================================================================
    // explainVerification
    // =============================================================================================================================

    private static String reasonTail(String name, Object verifyResult) {
        Object r = get(verifyResult, "reason");
        if (!(r instanceof String)) return null;
        String pre = name + ": ";
        return ((String) r).startsWith(pre) ? ((String) r).substring(pre.length()) : null;
    }

    private static String[] validityPinpoint(Object p, Object now) {
        Object exp = get(p, "exp"), iat = get(p, "iat");
        double lifetime = ExplainJs.toNum(exp) - ExplainJs.toNum(iat);
        if (!ExplainJs.gt(exp, iat)) {
            return new String[] {"exp " + s(exp) + " ≤ iat " + s(iat) + ": empty validity window", "set exp strictly greater than iat."};
        }
        if (lifetime > PCACTN_MAX_LIFETIME_MS) {
            return new String[] {"lifetime " + ExplainJs.numString(lifetime) + "ms exceeds the " + PCACTN_MAX_LIFETIME_MS + "ms maximum",
                "shorten the window to ≤ " + PCACTN_MAX_LIFETIME_MS + "ms (buildPCActn ttlMs)."};
        }
        if (now != UNDEF) {
            double nowN = ExplainJs.toNum(now);
            double iatN = ExplainJs.toNum(iat), expN = ExplainJs.toNum(exp);
            if (!(iatN <= nowN + PCACTN_MAX_SKEW_MS)) {
                return new String[] {"iat " + s(iat) + " is " + ExplainJs.numString(iatN - nowN) + "ms in the future (> " + PCACTN_MAX_SKEW_MS + "ms clock-skew allowance)",
                    "fix the signer clock; do not pre-date actions."};
            }
            if (!(nowN <= expN)) {
                return new String[] {"expired " + ExplainJs.numString(nowN - expN) + "ms ago (exp " + s(exp) + ", now " + s(now) + ")",
                    "build a fresh action — a PCActn lifetime is short by design."};
            }
        }
        return new String[] {"validity window invalid", "build a fresh action with a valid iat/exp window."};
    }

    private static final Pattern HOP = Pattern.compile("hop (\\d+)");

    /** {detail, remedy, hop-or-null}. */
    private static Object[] capChainPinpoint(Object p) {
        Object chain = get(p, "cap_chain");
        String reason;
        if (!(chain instanceof List)) reason = "cap_chain is not an array";
        else {
            @SuppressWarnings("unchecked") List<Object> l = (List<Object>) chain;
            String r = Pca.verifyChain(l, null, false, null);
            reason = r.isEmpty() ? "chain root is not the grant this verifier expects" : r;
        }
        Integer hop = null;
        Matcher mm = HOP.matcher(reason);
        if (mm.find()) hop = Integer.valueOf(mm.group(1));
        String remedy = "rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats.";
        if (reason.contains("root issuer") || reason.contains("not the grant")) remedy = "root the chain at the principal key that minted the grant.";
        else if (reason.contains("widens")) remedy = "a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation.";
        else if (reason.contains("caveat")) remedy = "attenuation is append-only: never drop, reorder or edit a parent caveat.";
        else if (reason.contains("signature")) remedy = "re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite).";
        return new Object[] {reason, remedy, hop};
    }

    private static Object[] leafSigPinpoint(Object p) {
        Object chain = get(p, "cap_chain");
        int idx = chain instanceof List ? ((List<?>) chain).size() - 1 : -1;
        Object leaf = idx >= 0 ? ((List<?>) chain).get(idx) : UNDEF;
        Object alg = nn(get(p, "alg"), "ed25519");
        String remedy = "sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder.";
        if (!truthy(leaf)) return new Object[] {"no leaf capability to check the signature against (empty/invalid chain)", remedy, null};
        return new Object[] {"leaf hop #" + idx + " signature (holder " + shorten(get(leaf, "holder")) + ", suite " + s(alg) + ") does not verify", remedy, idx >= 0 ? (Object) Integer.valueOf(idx) : null};
    }

    /** {detail, remedy, hop-or-null} of the decisive failing check. */
    private static Object[] pinpoint(String name, Object p, Object verifyResult, Object now) {
        String tail = reasonTail(name, verifyResult);
        Object action = opt(p, "action"), plan = opt(p, "plan");
        switch (name) {
            case "wire":
                return new Object[] {tail != null ? tail : "wire structure / strict-canonical-form check failed", "do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.", null};
            case "version":
                return new Object[] {tail != null ? tail : "unsupported ver " + num(get(p, "ver")) + " (verifier requires " + PCACTN_VERSION + ")", "re-mint the action at wire version " + PCACTN_VERSION + ".", null};
            case "audience":
                return new Object[] {tail != null ? tail : "aud " + ExplainJs.jstr(get(p, "aud")) + " does not match this resource server / instance",
                    "build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).", null};
            case "validity": {
                String[] v = validityPinpoint(p, now);
                return new Object[] {tail != null ? tail : v[0], v[1], null};
            }
            case "cap_chain": {
                Object[] c = capChainPinpoint(p);
                return new Object[] {tail != null ? tail : c[0], c[1], c[2]};
            }
            case "grant_ref_bound":
                return new Object[] {tail != null ? tail : "grant_ref " + shorten(get(p, "grant_ref")) + " is not the id of the root capability in cap_chain",
                    "set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant.", null};
            case "plan_inclusion":
                return new Object[] {tail != null ? tail : "action (verb " + ExplainJs.jstr(opt(action, "verb")) + " on " + ExplainJs.jstr(opt(action, "resource")) + ") is not node "
                    + ExplainJs.jstr(opt(plan, "node_id")) + " of committed plan " + shorten(opt(plan, "root")),
                    "rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).", null};
            case "leaf_signature": {
                Object[] l = leafSigPinpoint(p);
                return new Object[] {tail != null ? tail : l[0], l[1], l[2]};
            }
            case "counter":
            case "counter_format":
                return new Object[] {tail != null ? tail : "counter " + num(get(p, "counter")) + " is missing or not a non-negative safe integer",
                    "use a strictly increasing per-holder counter; a repeated counter is a replay.", null};
            case "malformed":
                return new Object[] {tail != null ? tail : "the PCActn is structurally malformed", "rebuild the action with the SDK; do not construct the wire object by hand.", null};
            default:
                return new Object[] {tail != null ? tail : name + " check failed", "satisfy the " + name + " requirement (supply the corresponding verifier hook / proof).", null};
        }
    }

    private static String passDetail(String name, Object p) {
        switch (name) {
            case "wire": return "wire structure + strict canonical form valid";
            case "version": return "ver " + num(get(p, "ver")) + " supported";
            case "audience": return "aud " + ExplainJs.jstr(get(p, "aud")) + " matches this resource server";
            case "validity": return "fresh: iat/exp window valid (lifetime " + num((ExplainJs.toNum(get(p, "exp")) - ExplainJs.toNum(get(p, "iat"))) / 1000) + "s)";
            case "cap_chain": {
                Object chain = get(p, "cap_chain");
                int len = chain instanceof List ? ((List<?>) chain).size() : 0;
                Object root = chain instanceof List && len > 0 ? ((List<?>) chain).get(0) : UNDEF;
                return len + "-hop chain verifies; root issuer " + shorten(opt(root, "issuer"));
            }
            case "grant_ref_bound": return "grant_ref " + shorten(get(p, "grant_ref")) + " is the id of the chain root";
            case "plan_inclusion": {
                Object plan = opt(p, "plan");
                return "action is node " + ExplainJs.jstr(opt(plan, "node_id")) + " of committed plan " + shorten(opt(plan, "root"));
            }
            case "leaf_signature": {
                Object chain = get(p, "cap_chain");
                Object leaf = chain instanceof List && !((List<?>) chain).isEmpty() ? ((List<?>) chain).get(((List<?>) chain).size() - 1) : UNDEF;
                return "leaf holder " + shorten(opt(leaf, "holder")) + " signature valid (suite " + s(nn(get(p, "alg"), "ed25519")) + ")";
            }
            case "counter":
            case "counter_format": return "counter " + num(get(p, "counter")) + " well-formed";
            default: return "ok";
        }
    }

    private static Map<String, Object> cleanCheck(Map<String, Object> c) {
        Map<String, Object> out = new LinkedHashMap<>(c);
        out.put("detail", cleanText(c.get("detail")));
        return out;
    }

    private static Map<String, Object> verificationResult(String verdict, boolean allow, List<Map<String, Object>> checks, Map<String, Object> decisive, String summary) {
        Map<String, Object> out = obj();
        out.put("kind", "verification");
        out.put("verdict", verdict);
        out.put("allow", allow);
        out.put("checks", new ArrayList<Object>(checks));
        List<Object> passed = new ArrayList<>(), failed = new ArrayList<>(), notEnforced = new ArrayList<>();
        for (Map<String, Object> c : checks) {
            Object st = c.get("status");
            if ("pass".equals(st)) passed.add(c.get("name"));
            if ("fail".equals(st)) failed.add(c.get("name"));
            if ("not-enforced".equals(st)) notEnforced.add(c.get("name"));
        }
        out.put("passed", passed);
        out.put("failed", failed);
        out.put("notEnforced", notEnforced);
        if (decisive != null) out.put("decisive", decisive);
        out.put("summary", summary);
        return out;
    }

    private static Map<String, Object> deniedVerification(String why) {
        Map<String, Object> e = obj();
        e.put("name", "malformed");
        e.put("status", "fail");
        e.put("title", CHECK_TITLE.get("malformed"));
        e.put("detail", why);
        e.put("remedy", "pass the PCActn and the verifier result you verified.");
        e.put("decisive", true);
        return verificationResult("deny", false, List.of(e), e, "Denied: " + why);
    }

    private static List<Object> chars(String t) {
        List<Object> out = new ArrayList<>();
        for (int i = 0; i < t.length(); i++) out.add(String.valueOf(t.charAt(i)));
        return out;
    }

    /**
     * Explain the offline verification of a PCActn: walk the normative checks in order; for each PASS summarize what held and
     * for the FIRST failing check pinpoint it with a concrete remedy. {@code opts.now} (epoch ms) refines the validity pinpoint.
     */
    public static Map<String, Object> explainVerification(Object pcActn, Object verifyResult, Object opts) {
        if (!ExplainJs.isObject(pcActn) || !ExplainJs.isObject(verifyResult)) return deniedVerification("the PCActn or the verifier result is missing");
        try {
            return explainVerificationInner(pcActn, verifyResult, opts);
        } catch (RuntimeException | StackOverflowError e) {
            return deniedVerification("the PCActn or the verifier result is malformed");
        }
    }

    private static Map<String, Object> explainVerificationInner(Object p, Object vr, Object opts) {
        Object statuses = nn(get(vr, "checks"), new LinkedHashMap<String, Object>());
        List<String> ordered = new ArrayList<>(VERIFY_CHECK_ORDER);
        Set<String> seen = new HashSet<>(VERIFY_CHECK_ORDER);
        for (String n : ExplainJs.keys(statuses)) if (!seen.contains(n)) ordered.add(n);

        String decisiveName = null;
        for (String n : ordered) if ("fail".equals(get(statuses, n))) { decisiveName = n; break; }

        List<Map<String, Object>> checks = new ArrayList<>();
        Map<String, Object> decisive = null;
        for (String name : ordered) {
            Object raw = get(statuses, name);
            Object status = nn(raw, "skipped");
            String title = CHECK_TITLE.containsKey(name) ? CHECK_TITLE.get(name) : name;
            String detail;
            String remedy = null;
            Integer hop = null;
            if ("fail".equals(status)) {
                Object[] pin = pinpoint(name, p, vr, rd(opts, "now"));
                detail = (String) pin[0];
                remedy = (String) pin[1];
                hop = (Integer) pin[2];
            } else if ("pass".equals(status)) detail = passDetail(name, p);
            else if ("not-enforced".equals(status)) detail = "not enforced by this verifier (no hook / opt-out)";
            else if ("unsupported".equals(status)) detail = "the PCActn carries a feature this verifier does not implement (never a pass)";
            else detail = "not reached (a terminal earlier check stopped evaluation)";
            Map<String, Object> entry = obj();
            entry.put("name", name);
            entry.put("status", status);
            entry.put("title", title);
            entry.put("detail", detail);
            if (remedy != null) entry.put("remedy", remedy);
            if (hop != null) entry.put("hop", ExplainJs.n(hop));
            if (name.equals(decisiveName)) { entry.put("decisive", true); decisive = entry; }
            checks.add(entry);
        }

        Object checksRaw = get(vr, "checks");
        boolean hasChecks = checksRaw instanceof Map;
        boolean claimedAllow = Boolean.TRUE.equals(get(vr, "allow")) && hasChecks;
        boolean contradicted = claimedAllow && decisiveName != null;
        String verdict = claimedAllow && !contradicted ? "allow" : "deny";
        String summary;
        if (verdict.equals("allow")) {
            int pass = 0;
            for (Map<String, Object> c : checks) if ("pass".equals(c.get("status"))) pass++;
            summary = "All " + pass + " evaluated checks passed (no check failed).";
        } else if (Boolean.TRUE.equals(get(vr, "allow")) && !hasChecks) {
            summary = "Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial).";
        } else if (contradicted) {
            summary = "Denied: the verifier result says allow but the \"" + (decisive != null ? s(decisive.get("title")) : decisiveName) + "\" check failed (inconsistent result, treated as a denial).";
        } else if (decisive != null) {
            summary = "Denied at the \"" + s(decisive.get("title")) + "\" check: " + s(decisive.get("detail"));
        } else {
            Object reason = get(vr, "reason");
            summary = "Denied: " + (reason instanceof String ? (String) reason : "a check failed");
        }
        List<Map<String, Object>> cleaned = new ArrayList<>();
        for (Map<String, Object> c : checks) cleaned.add(cleanCheck(c));
        return verificationResult(verdict, verdict.equals("allow"), cleaned, decisive != null ? cleanCheck(decisive) : null, cleanText(summary));
    }

    private static final Map<String, String> GLYPH = Map.of("pass", "✓", "fail", "✗", "not-enforced", "·", "unsupported", "?", "skipped", "–");

    /** Render a verification explanation. */
    public static String verificationToText(Map<String, Object> e) {
        List<String> lines = new ArrayList<>();
        lines.add("PCA verification — " + s(e.get("verdict")).toUpperCase(java.util.Locale.ROOT));
        lines.add(s(e.get("summary")));
        lines.add("");
        for (Object co : (List<?>) e.get("checks")) {
            Map<?, ?> c = (Map<?, ?>) co;
            String mark = truthy(c.get("decisive")) ? " ◀ DECISIVE" : "";
            Object st = c.get("status");
            String glyph = st instanceof String && GLYPH.containsKey(st) ? GLYPH.get(st) : "undefined";
            lines.add("  " + glyph + " " + padEnd(s(c.get("name")), 16) + " " + s(c.get("detail")) + mark);
            if (truthy(c.get("decisive")) && truthy(c.get("remedy"))) lines.add("      ↳ fix: " + s(c.get("remedy")));
        }
        return String.join("\n", lines);
    }

    // =============================================================================================================================
    // explainDecision
    // =============================================================================================================================

    private static String caveatRemedy(String type, Map<String, Object> rest) {
        switch (type) {
            case "expires": return "the grant expired at " + num(g(rest, "at")) + " (epoch ms); obtain a fresh grant or re-mint with a later 'expires'.";
            case "not_before": return "the grant is not valid until " + num(g(rest, "at")) + " (epoch ms); retry after that time.";
            case "rate": return "rate limit " + num(g(rest, "max")) + "/" + num(g(rest, "per_secs")) + "s reached; wait for the window to clear or raise the 'rate' caveat.";
            case "max_blast_radius": return "the action's blast radius exceeds the caveat max " + num(g(rest, "max")) + "; narrow the action or raise 'max_blast_radius'.";
            case "reversibility_max": return "the action is more severe than the allowed class '" + s(g(rest, "class")) + "'; only that class or lower is permitted.";
            case "delegation_depth": return "delegation depth exceeds max " + num(g(rest, "max")) + "; act from a shallower hop or raise 'delegation_depth'.";
            default: return "caveat '" + type + "' is not satisfied; check its parameters against the action/context.";
        }
    }

    private static Object g(Map<String, Object> m, String k) { return m.containsKey(k) ? m.get(k) : UNDEF; }

    private static String caveatDetail(String type, Map<String, Object> rest, Object satisfied) {
        String bound = valueSummary(rest);
        String verb = truthy(satisfied) ? "held" : "NARROWED/DENIED";
        return bound.length() > 0 ? type + "(" + bound + ") " + verb : type + " " + verb;
    }

    private static final Pattern FAILED_CAVEATS = Pattern.compile("caveat\\(s\\) not satisfied: ([^\\n\\r\\u2028\\u2029]+)\\z");

    private static Set<String> failedCaveatTypesFromReasons(List<Object> reasons) {
        Set<String> out = new HashSet<>();
        for (Object r : reasons) {
            Matcher mm = FAILED_CAVEATS.matcher(str(r));
            if (mm.find()) for (String t : mm.group(1).split(",", -1)) { String tt = ExplainJs.jsTrim(t); if (!tt.isEmpty()) out.add(tt); }
        }
        return out;
    }

    private static String riskBand(Object r, Object theta1, Object theta2, Object tier) {
        if (theta1 == UNDEF || theta2 == UNDEF) return "effective tier t=" + s(tier);
        double rn = ExplainJs.toNum(r);
        if (rn <= ExplainJs.toNum(theta1)) return "r " + num(r) + " ≤ θ1 " + num(theta1) + " → claim band (t=1)";
        if (rn <= ExplainJs.toNum(theta2)) return "θ1 " + num(theta1) + " < r " + num(r) + " ≤ θ2 " + num(theta2) + " → standard band (t=2)";
        return "r " + num(r) + " > θ2 " + num(theta2) + " → strong band (t=3)";
    }

    private static Map<String, Object> noDecision(String reason) {
        Map<String, Object> d = obj();
        d.put("admit", false);
        d.put("needStepUp", false);
        d.put("releaseGuardianShare", false);
        d.put("r", ExplainJs.n(1));
        Map<String, Object> rt = obj();
        rt.put("t", ExplainJs.n(3));
        rt.put("proof", "human");
        rt.put("optimisticAllowed", false);
        d.put("requiredThreshold", rt);
        Map<String, Object> b = obj();
        b.put("B", ExplainJs.n(0));
        b.put("tau", ExplainJs.n(0));
        b.put("asOf", ExplainJs.n(0));
        d.put("budget", b);
        d.put("reasons", new ArrayList<Object>(List.of(reason)));
        return d;
    }

    /**
     * Explain a Policy-VM decision: which predicate granted the action, which caveat narrowed or denied it, the risk band and
     * the admission path. {@code opts} may carry {@code envelope} and {@code context} ({action, caveat, chain}).
     */
    public static Map<String, Object> explainDecision(Object pcActn, Object decision, Object opts) {
        Object o = opts;
        if (!(decision instanceof Map || decision instanceof List) || !ExplainJs.isObject(get(decision, "requiredThreshold"))) {
            return explainDecisionInner(noDecision("no policy decision supplied (default-deny)"), o);
        }
        try {
            return explainDecisionInner(decision, o);
        } catch (RuntimeException | StackOverflowError e) {
            return explainDecisionInner(noDecision("the policy decision could not be explained (default-deny)"), new LinkedHashMap<>());
        }
    }

    private static int len(Object o) {
        if (o instanceof List) return ((List<?>) o).size();
        if (o instanceof String) return ((String) o).length();
        return -1;
    }

    private static Map<String, Object> explainDecisionInner(Object decision, Object opts) {
        Object envO = rd(opts, "envelope");
        Object env = envO == null ? UNDEF : envO;
        Object ctxO = get(opts, "context");
        Object ctx = nn(ctxO, new LinkedHashMap<String, Object>());
        Object reasonsRaw = get(decision, "reasons");
        List<Object> reasons = new ArrayList<>();
        if (reasonsRaw instanceof List) reasons.addAll((List<?>) reasonsRaw);

        boolean admitted = Boolean.TRUE.equals(get(decision, "admit"));
        Object rgs = get(decision, "releaseGuardianShare");
        String disposition = admitted ? "auto-admit" : Boolean.TRUE.equals(rgs) ? "step-up" : "denied";
        String verdict = admitted ? "allow" : "deny";

        Map<String, Object> grant = obj();
        put(grant, "granted", rgs);
        Object chain = get(ctx, "chain");
        Object rootCap = opt(chain, "0");
        if (truthy(rootCap)) put(grant, "capabilityId", get(rootCap, "id"));
        Object ctxAction = get(ctx, "action");
        Object ctxCaveat = get(ctx, "caveat");
        if (truthy(env) && truthy(ctxAction)) {
            Object preds = rd(env, "predicates");
            Object[] pr = evalPredicates(preds, ctxAction);
            if (pr[0] == Boolean.TRUE) {
                grant.put("granted", true);
                grant.put("predicate", pr[1]);
                grant.put("predicateIndex", ExplainJs.n((Integer) pr[2]));
                grant.put("where", whereSummary(get(pr[1], "where")));
            } else {
                grant.put("granted", false);
                grant.put("reason", pr[1] != null ? pr[1] : "no predicate permits this action");
            }
        } else if (!truthy(rgs)) {
            for (Object r : reasons) {
                String rs = strictStr(r);
                if (rs.contains("predicate") || rs.contains("not permitted")) { grant.put("reason", rs); break; }
            }
        }

        List<Map<String, Object>> caveats = new ArrayList<>();
        Set<String> failedFromReasons = failedCaveatTypesFromReasons(reasons);
        boolean canEval = env != UNDEF && ctxCaveat != UNDEF && ctxAction != UNDEF;

        Object grantCaveats = nn(opt(env, "caveats"), new ArrayList<Object>());
        if (grantCaveats instanceof String) grantCaveats = chars((String) grantCaveats); // for-of over a string yields its characters
        if (!(grantCaveats instanceof List)) throw new IllegalArgumentException("TypeError: not iterable");
        Object chain0 = opt(chain, "0");
        int rootCount = 0;
        if (chain0 != UNDEF && chain0 != null) {
            Object cv0 = rd(chain0, "caveats");
            if (cv0 == UNDEF || cv0 == null) throw new IllegalArgumentException("TypeError: caveats.length");
            rootCount = Math.max(0, len(cv0));
        }
        List<Object> delegated = new ArrayList<>();
        if (chain instanceof List && ((List<?>) chain).size() > 1) {
            List<?> cl = (List<?>) chain;
            Object leaf = cl.get(cl.size() - 1);
            Object lc = nn(opt(leaf, "caveats"), new ArrayList<Object>());
            if (lc instanceof String) lc = chars((String) lc);
            if (!(lc instanceof List)) throw new IllegalArgumentException("TypeError: slice");
            List<?> l = (List<?>) lc;
            if (rootCount < l.size()) delegated.addAll(l.subList(rootCount, l.size()));
        }
        for (Object cv : (List<?>) grantCaveats) caveats.add(classify(cv, false, canEval, ctxCaveat, ctxAction, failedFromReasons, rgs));
        for (Object cv : delegated) caveats.add(classify(cv, true, canEval, ctxCaveat, ctxAction, failedFromReasons, rgs));

        Object rt = get(decision, "requiredThreshold");
        Object r = get(decision, "r");
        Object riskPolicy = UNDEF;
        if (env != UNDEF) {
            riskPolicy = rd(env, "risk_policy");
            if (riskPolicy == UNDEF || riskPolicy == null) throw new IllegalArgumentException("TypeError: risk_policy is undefined");
        }
        Object theta1 = opt(riskPolicy, "theta1"), theta2 = opt(riskPolicy, "theta2");
        Object tier = get(rt, "t"), proof = get(rt, "proof"), optimistic = get(rt, "optimisticAllowed");
        Map<String, Object> risk = obj();
        put(risk, "r", r);
        put(risk, "tier", tier);
        put(risk, "proof", proof);
        put(risk, "optimisticAllowed", optimistic);
        risk.put("band", riskBand(r, theta1, theta2, tier));
        if (env != UNDEF) {
            put(risk, "theta1", theta1);
            put(risk, "theta2", theta2);
        }

        Object kappa = env == UNDEF ? UNDEF : get(riskPolicy, "kappa");
        Double costVal = kappa != UNDEF ? cost(r, kappa) : null;
        boolean budgetDepleted = false;
        for (Object rr : reasons) if (strictStr(rr).contains("budget depleted")) { budgetDepleted = true; break; }
        String path;
        if (admitted) path = "auto-admitted at t=" + s(tier) + " (" + s(proof) + "); metered";
        else if (!truthy(rgs)) path = "guardian share withheld — policy not satisfied (no autonomous or guardian path)";
        else if (budgetDepleted) path = "trust budget cannot cover the cost — step-up to t=3 (human recharge) required";
        else path = "step-up to t=" + s(tier) + " (" + s(proof) + ") co-signature required";
        Map<String, Object> admission = obj();
        admission.put("admit", admitted);
        put(admission, "needStepUp", get(decision, "needStepUp"));
        put(admission, "releaseGuardianShare", rgs);
        put(admission, "budget", get(decision, "budget"));
        admission.put("path", path);
        if (costVal != null) admission.put("cost", costVal);
        if (kappa != UNDEF) put(admission, "kappa", kappa);

        Map<String, Object> decisive = null;
        if (!admitted) {
            decisive = obj();
            if (!truthy(grant.get("granted"))) {
                decisive.put("reason", grant.containsKey("reason") && grant.get("reason") != null ? grant.get("reason") : "action not permitted by the envelope predicates (default-deny)");
                decisive.put("remedy", "grant a predicate that permits this verb+resource (and satisfies its where bound).");
            } else {
                Map<String, Object> firstFailed = null;
                for (Map<String, Object> c : caveats) if (!truthy(c.get("satisfied"))) { firstFailed = c; break; }
                if (firstFailed != null) {
                    decisive.put("reason", "caveat '" + firstFailed.get("type") + "' narrowed the authority away: " + firstFailed.get("detail"));
                    if (truthy(firstFailed.get("remedy"))) decisive.put("remedy", firstFailed.get("remedy"));
                } else if (budgetDepleted) {
                    decisive.put("reason", "risk " + num(r) + " is admissible but the trust budget cannot cover cost κ·r" + (costVal != null ? "=" + num(costVal) : ""));
                    decisive.put("remedy", "recharge the budget with a human co-sign, or lower the action risk.");
                } else {
                    decisive.put("reason", "risk " + num(r) + " exceeds the auto threshold → step-up to t=" + s(tier) + " (" + s(proof) + ")");
                    decisive.put("remedy", ExplainJs.numOf(tier) != null && ExplainJs.numOf(tier) == 3.0 ? "obtain a human step-up co-signature." : "obtain the guardian/principal co-signature for this tier.");
                }
            }
        }

        String summary;
        if (admitted) {
            summary = "Auto-admitted: " + (truthy(grant.get("predicate")) ? "predicate #" + s(grant.get("predicateIndex")) : "policy")
                + " grants it, all caveats held, risk r=" + num(r) + " is in the t=" + s(tier) + " band and the budget covers it.";
        } else if (decisive != null) {
            summary = ("deny".equals(verdict) && "denied".equals(disposition) ? "Denied" : "Needs step-up") + ": " + s(decisive.get("reason"));
        } else summary = "Not auto-admitted (t=" + s(tier) + ").";

        List<Object> cleanedCaveats = new ArrayList<>();
        for (Map<String, Object> c : caveats) {
            Map<String, Object> cc = new LinkedHashMap<>(c);
            cc.put("detail", cleanText(c.get("detail")));
            cleanedCaveats.add(cc);
        }
        Map<String, Object> cleanedDecisive = null;
        if (decisive != null) { cleanedDecisive = new LinkedHashMap<>(decisive); cleanedDecisive.put("reason", cleanText(decisive.get("reason"))); }
        List<Object> reasonOut = new ArrayList<>();
        for (Object rr : reasons) reasonOut.add(cleanText(rr));

        Map<String, Object> out = obj();
        out.put("kind", "decision");
        out.put("verdict", verdict);
        out.put("disposition", disposition);
        out.put("grant", grant);
        out.put("caveats", cleanedCaveats);
        out.put("risk", risk);
        out.put("admission", admission);
        if (cleanedDecisive != null) out.put("decisive", cleanedDecisive);
        out.put("reasons", reasonOut);
        out.put("summary", cleanText(summary));
        return out;
    }

    /** {@code r.includes(...)} on a reason: only strings have it (anything else is a TypeError, caught by the caller). */
    private static String strictStr(Object r) {
        if (!(r instanceof String)) throw new IllegalArgumentException("TypeError: includes is not a function");
        return (String) r;
    }

    /** {allowed(Boolean), matched predicate or reason(String), index}. */
    private static Object[] evalPredicates(Object predicates, Object actionCtx) {
        try {
            if (!(predicates instanceof List) || ((List<?>) predicates).isEmpty()) return new Object[] {Boolean.FALSE, "envelope grants no predicates", null};
            Map<String, Object> ac = mapOrEmpty(actionCtx);
            List<?> ps = (List<?>) predicates;
            for (int i = 0; i < ps.size(); i++) {
                Object pi = ps.get(i);
                if (pi != null && Predicates.evaluatePredicates(java.util.Collections.singletonList(pi), ac)) return new Object[] {Boolean.TRUE, pi, i};
            }
            return new Object[] {Boolean.FALSE, Predicates.denialReason(predicates, ac), null};
        } catch (RuntimeException | StackOverflowError e) {
            return new Object[] {Boolean.FALSE, "predicate evaluation error (fail closed)", null};
        }
    }

    private static double cost(Object r, Object kappa) {
        Double k = ExplainJs.numOf(kappa);
        double kk = k != null && !k.isNaN() && !k.isInfinite() && k > 0 ? k : 0;
        Double rr = ExplainJs.numOf(r);
        double rv = rr != null && !rr.isNaN() && !rr.isInfinite() ? rr : 1;
        return kk * (rv < 0 ? 0 : rv > 1 ? 1 : rv);
    }

    private static Map<String, Object> classify(Object cv, boolean delegated, boolean canEval, Object caveatCtx, Object actionCtx, Set<String> failedFromReasons, Object rgs) {
        String type = typeOf(cv);
        Map<String, Object> rest = caveatRest(cv);
        Object satisfied;
        if (canEval && truthy(caveatCtx) && truthy(actionCtx)) satisfied = evalCaveat(cv, caveatCtx, actionCtx);
        else satisfied = failedFromReasons.contains(type) ? (Object) Boolean.FALSE : rgs;
        Map<String, Object> o = obj();
        o.put("type", type);
        put(o, "satisfied", satisfied);
        o.put("value", rest);
        o.put("detail", caveatDetail(type, rest, satisfied));
        o.put("delegated", delegated);
        if (!truthy(satisfied)) o.put("remedy", caveatRemedy(type, rest));
        return o;
    }

    /** {@code evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok}: the camelCase TS context mapped onto the native evaluator's. */
    private static boolean evalCaveat(Object cv, Object caveatCtx, Object actionCtx) {
        Map<String, Object> inner = mapOrEmpty(get(actionCtx, "action"));
        Map<String, Object> c = obj();
        c.put("now", nullIfUndef(get(caveatCtx, "now")));
        c.put("action", inner);
        c.put("delegation_depth", nullIfUndef(get(caveatCtx, "delegationDepth")));
        c.put("blast_radius", nullIfUndef(get(caveatCtx, "blastRadius")));
        c.put("reversibility_class", nullIfUndef(get(caveatCtx, "reversibilityClass")));
        c.put("recent_action_times", nullIfUndef(get(caveatCtx, "recentActionTimes")));
        Map<String, Object> tool = obj();
        tool.put("tool", nullIfUndef(get(inner, "verb")));
        tool.put("args", nullIfUndef(get(inner, "params")));
        Caveats.Result res = Authorize.evaluateAgentCaveats(new ArrayList<Object>(List.of(cv == null ? Boolean.FALSE : cv)), c, mapOrEmpty(actionCtx), tool);
        return res.ok;
    }

    private static Object nullIfUndef(Object o) { return o == UNDEF ? null : o; }

    /** Render a decision explanation. */
    public static String decisionToText(Map<String, Object> e) {
        List<String> lines = new ArrayList<>();
        lines.add("PCA decision — " + s(e.get("verdict")).toUpperCase(java.util.Locale.ROOT) + " (" + s(e.get("disposition")) + ")");
        lines.add(s(e.get("summary")));
        lines.add("");
        Object gr = e.get("grant");
        Object pred = get(gr, "predicate");
        if (truthy(get(gr, "granted")) && truthy(pred)) {
            Object pv = get(pred, "verb");
            String verbs = pv instanceof List ? joinPipe((List<?>) pv) : s(pv);
            Object res = get(pred, "resource");
            lines.add("  authority : predicate #" + s(get(gr, "predicateIndex")) + " of grant " + shorten(get(gr, "capabilityId")) + " grants " + verbs + " on " + s(nn(res, "*")));
            lines.add("              where " + s(get(gr, "where")));
        } else {
            lines.add("  authority : NOT granted — " + s(nn(get(gr, "reason"), "no predicate permits this action")));
        }
        List<?> cvs = (List<?>) e.get("caveats");
        if (cvs.isEmpty()) lines.add("  caveats   : none");
        else {
            for (Object co : cvs) {
                Map<?, ?> c = (Map<?, ?>) co;
                String mark = truthy(c.get("satisfied")) ? "✓" : "✗";
                String src = truthy(c.get("delegated")) ? " [delegated]" : "";
                lines.add("  caveat " + mark + "  : " + s(c.get("detail")) + src);
                if (!truthy(c.get("satisfied")) && truthy(c.get("remedy"))) lines.add("              ↳ fix: " + s(c.get("remedy")));
            }
        }
        Object risk = e.get("risk");
        lines.add("  risk      : " + s(get(risk, "band")) + "; proof=" + s(get(risk, "proof")) + ", optimistic=" + s(get(risk, "optimisticAllowed")));
        Object a = e.get("admission");
        Object cost = get(a, "cost");
        String costStr = cost != UNDEF ? ", cost κ·r=" + num(cost) + " (κ=" + num(get(a, "kappa")) + ")" : "";
        lines.add("  budget    : " + s(get(a, "path")) + costStr + "; B after=" + num(rd(get(a, "budget"), "B")));
        Object dec = e.get("decisive");
        if (dec != null) {
            lines.add("");
            lines.add("  ◀ DECISIVE: " + s(get(dec, "reason")));
            if (truthy(get(dec, "remedy"))) lines.add("      ↳ fix: " + s(get(dec, "remedy")));
        }
        return String.join("\n", lines);
    }

    private static String joinPipe(List<?> l) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Object x : l) {
            if (!first) sb.append('|');
            first = false;
            if (x != null) sb.append(s(x));
        }
        return sb.toString();
    }

    // =============================================================================================================================
    // explainChain
    // =============================================================================================================================

    private static boolean isBudgetAlloc(Object cv) {
        if (!(cv instanceof Map) || !"budget_alloc".equals(((Map<?, ?>) cv).get("type"))) return false;
        Object l = ((Map<?, ?>) cv).get("limit");
        return ExplainJs.isFiniteNumber(l) && ExplainJs.numOf(l) >= 0;
    }

    private static String hopNarrowedSummary(boolean isRoot, List<?> added) {
        List<String> bits = new ArrayList<>();
        for (Object cv : added) {
            String type = typeOf(cv);
            Map<String, Object> rest = caveatRest(cv);
            if (type.equals("envelope")) {
                Object preds = rest.get("predicates"), inner = rest.get("caveats");
                bits.add("envelope (" + (preds instanceof List ? ((List<?>) preds).size() : 0) + " predicate(s), " + (inner instanceof List ? ((List<?>) inner).size() : 0) + " caveat(s))");
            } else if (isBudgetAlloc(cv)) {
                bits.add("budget_alloc(B_sub=" + num(((Map<?, ?>) cv).get("limit")) + ")");
            } else {
                String bound = valueSummary(rest);
                bits.add(!bound.isEmpty() ? "+" + type + "(" + bound + ")" : "+" + type);
            }
        }
        if (bits.isEmpty()) return isRoot ? "root grant (no caveats)" : "rebind only (no new caveats)";
        return (isRoot ? "grants " : "narrows: ") + String.join(", ", bits);
    }

    /** The per-node budget subtree carried by a chain (one node per well-formed {@code budget_alloc} caveat, root to leaf). */
    public static List<Object> budgetAllocNodes(Object chain) {
        List<Object> out = new ArrayList<>();
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return out;
        List<?> ch = (List<?>) chain;
        Object leaf = ch.get(ch.size() - 1);
        Object lcv = rd(leaf, "caveats");
        if (!(lcv instanceof List)) return out;
        List<?> lc = (List<?>) lcv;
        int hop = 0;
        for (int ci = 0; ci < lc.size(); ci++) {
            while (hop < ch.size() - 1) {
                Object cvs = rd(ch.get(hop), "caveats");
                int n = cvs == UNDEF || cvs == null ? 0 : Math.max(0, len(cvs));
                if (n <= ci) hop++; else break;
            }
            Object cv = lc.get(ci);
            if (!isBudgetAlloc(cv)) continue;
            Object introducing = ch.get(hop);
            Map<String, Object> d = obj();
            d.put("d", "atlas-pca/budget-node/v1");
            d.put("cap", rd(introducing, "id"));
            d.put("i", ExplainJs.n(ci));
            Map<String, Object> node = obj();
            node.put("nodePath", Pca.hashCanonical(d));
            put(node, "capId", rd(introducing, "id"));
            put(node, "holder", rd(introducing, "holder"));
            node.put("depth", ExplainJs.n(hop));
            node.put("caveatIndex", ExplainJs.n(ci));
            node.put("limit", ((Map<?, ?>) cv).get("limit"));
            out.add(node);
        }
        return out;
    }

    /**
     * Render a capability delegation chain as an ordered attenuation trace. With {@code opts.verify === true} the chain is also
     * checked ({@code opts.expectedRootIssuer} pins the root issuer); otherwise the trace shows what the chain only CLAIMS.
     */
    public static Map<String, Object> explainChain(Object chain, Object opts) {
        Map<String, Object> out = explainChainInner(chain);
        if (!Boolean.TRUE.equals(rd(opts, "verify"))) return out;
        boolean ok = false;
        String reason = "chain is not an array";
        try {
            if (chain instanceof List) {
                @SuppressWarnings("unchecked") List<Object> l = (List<Object>) chain;
                Object exp = get(opts, "expectedRootIssuer");
                String r = exp instanceof String ? Pca.verifyChain(l, (String) exp, true, null) : Pca.verifyChain(l, null, false, null);
                ok = r.isEmpty();
                reason = ok ? null : r;
            }
        } catch (RuntimeException e) {
            reason = "chain could not be verified";
        }
        Map<String, Object> v = obj();
        v.put("ok", ok);
        if (reason != null) v.put("reason", cleanText(reason));
        Map<String, Object> res = new LinkedHashMap<>(out);
        res.put("verification", v);
        return res;
    }

    private static Map<String, Object> explainChainInner(Object chain) {
        List<Object> safe = chain instanceof List ? new ArrayList<>((List<?>) chain) : new ArrayList<>();
        List<Object> hops = new ArrayList<>();
        for (int i = 0; i < safe.size(); i++) {
            Object cap = safe.get(i);
            if (!truthy(cap)) continue;
            boolean isRoot = i == 0;
            Object parent = i > 0 ? safe.get(i - 1) : UNDEF;
            Object pc = truthy(parent) ? get(parent, "caveats") : UNDEF;
            int parentLen = pc instanceof List ? ((List<?>) pc).size() : 0;
            Object oc = get(cap, "caveats");
            List<?> own = oc instanceof List ? (List<?>) oc : List.of();
            List<?> added = isRoot ? own : own.size() >= parentLen ? own.subList(parentLen, own.size()) : List.of();
            Object budgetCv = null;
            for (Object cv : added) if (isBudgetAlloc(cv)) { budgetCv = cv; break; }
            Map<String, Object> hop = obj();
            hop.put("index", ExplainJs.n(i));
            hop.put("isRoot", isRoot);
            put(hop, "issuer", get(cap, "issuer"));
            put(hop, "holder", get(cap, "holder"));
            hop.put("issuerShort", shorten(get(cap, "issuer")));
            hop.put("holderShort", shorten(get(cap, "holder")));
            hop.put("alg", nn(get(cap, "alg"), "ed25519"));
            hop.put("addedCaveats", new ArrayList<Object>(added));
            List<Object> types = new ArrayList<>();
            for (Object cv : added) types.add(typeOf(cv));
            hop.put("addedCaveatTypes", types);
            hop.put("narrowed", cleanText(hopNarrowedSummary(isRoot, added)));
            if (budgetCv != null) hop.put("budgetAlloc", ((Map<?, ?>) budgetCv).get("limit"));
            hops.add(hop);
        }
        Object root = safe.isEmpty() ? UNDEF : safe.get(0);
        Object leaf = safe.isEmpty() ? UNDEF : safe.get(safe.size() - 1);
        List<Object> nodes = budgetAllocNodes(safe);
        String summary = safe.isEmpty() ? "empty chain (no authority)"
            : shorten(opt(root, "issuer")) + " (principal) delegated through " + (safe.size() - 1) + " hop(s) to the acting holder " + shorten(opt(leaf, "holder")) + "; " + nodes.size() + " budget node(s).";
        Map<String, Object> out = obj();
        out.put("kind", "chain");
        out.put("depth", ExplainJs.n(safe.size()));
        out.put("hops", hops);
        put(out, "rootIssuer", opt(root, "issuer"));
        put(out, "leafHolder", opt(leaf, "holder"));
        out.put("budgetNodes", nodes);
        out.put("summary", summary);
        return out;
    }

    /** Render a chain explanation. */
    public static String chainToText(Map<String, Object> e) {
        List<String> lines = new ArrayList<>();
        lines.add("PCA delegation chain — " + s(e.get("depth")) + " hop(s) (attenuation trace)");
        Object v = e.get("verification");
        if (v == null) lines.add("UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.");
        else if (truthy(get(v, "ok"))) lines.add("verified: signatures, links and caveat rules hold.");
        else lines.add("NOT VALID: " + s(nn(get(v, "reason"), "the chain failed verification")));
        lines.add(s(e.get("summary")));
        lines.add("");
        for (Object ho : (List<?>) e.get("hops")) {
            Map<?, ?> h = (Map<?, ?>) ho;
            String tag = truthy(h.get("isRoot")) ? "root " : "deleg";
            lines.add("  #" + s(h.get("index")) + " " + tag + " " + s(h.get("issuerShort")) + " ──▶ " + s(h.get("holderShort")) + "   " + s(h.get("narrowed")));
        }
        List<?> nodes = (List<?>) e.get("budgetNodes");
        if (!nodes.isEmpty()) {
            List<String> tree = new ArrayList<>();
            for (Object no : nodes) tree.add("depth " + s(((Map<?, ?>) no).get("depth")) + " B_sub=" + num(((Map<?, ?>) no).get("limit")));
            lines.add("");
            lines.add("  budget subtree: " + String.join(" → ", tree));
        }
        return String.join("\n", lines);
    }
}
