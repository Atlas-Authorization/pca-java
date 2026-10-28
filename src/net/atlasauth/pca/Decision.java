package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The ternary decision, the tighten-only model rule (rule 21) and the units check (rule 20): a port of the TypeScript
 * {@code decision.ts} / {@code envelope-rules.ts}. {@code deny < escalate < allow}; {@link #meet} (the minimum) is the only
 * combinator, so {@code escalate} never becomes {@code allow} by composition. Every function is total (no exception
 * escapes); anything malformed fails closed (deny / not ok).
 *
 * <p>Inputs are {@link Json} trees (maps, lists, strings, booleans, {@link Json.Num}). A member that is ABSENT differs from
 * a member that is JSON {@code null}, as {@code undefined} differs from {@code null} in the reference.
 */
public final class Decision {
    private Decision() {}

    public static final String DENY = "deny";
    public static final String ESCALATE = "escalate";
    public static final String ALLOW = "allow";
    public static final int MAX_TIGHTEN_RULES = 64;

    /** A failing check is escalate-class iff its reason (after {@code <check>: }) starts with one of these. */
    public static final List<String> ESCALATE_REASON_PREFIXES = List.of("intent_required:", "escalate:");

    private static final Pattern NAME_RE = Pattern.compile("[a-z][a-z0-9_]{0,63}");
    private static final Pattern PARAM_PATH_RE = Pattern.compile("action\\.params\\.[A-Za-z0-9_-]{1,64}");
    private static final List<String> MODEL_ENV_ROOTS = List.of("class", "prov", "judge", "detect");

    private static int rank(String d) {
        if (DENY.equals(d)) return 0;
        if (ESCALATE.equals(d)) return 1;
        if (ALLOW.equals(d)) return 2;
        return -1;
    }

    /** The lower of two decisions; an unknown value (or null) is {@code deny}. */
    public static String meet(String a, String b) {
        int x = rank(a), y = rank(b);
        if (x < 0 || y < 0) return DENY;
        return x <= y ? a : b;
    }

    /** The highest decision a model signal permits: ok -> allow, escalate -> escalate, anything else -> deny. */
    public static String signalCeiling(Object s) {
        if ("ok".equals(s)) return ALLOW;
        if ("escalate".equals(s)) return ESCALATE;
        return DENY;
    }

    /** G-T9: a model can only move a decision down. */
    public static String tighten(String base, Object signal) { return meet(base, signalCeiling(signal)); }

    /** {@code d === 'escalate' && answered === true ? 'allow' : d}: anything but an answered escalate is returned UNCHANGED. */
    public static String pepDecision(String d, Object answered) {
        return ESCALATE.equals(d) && Boolean.TRUE.equals(answered) ? ALLOW : d;
    }

    private static final Pattern ARRAY_INDEX = Pattern.compile("0|[1-9][0-9]{0,9}");

    /** {@code Object.keys} order of a parsed object: canonical array-index keys first (ascending), then the rest in text order. */
    static List<String> jsKeys(Map<?, ?> m) {
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (Object o : m.keySet()) {
            String k = (String) o;
            if (ARRAY_INDEX.matcher(k).matches() && Long.parseLong(k) < 4294967295L) idx.add(k); else rest.add(k);
        }
        idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        idx.addAll(rest);
        return idx;
    }

    // ---- decisionOf --------------------------------------------------------------------------------------------------

    private static boolean escalateBody(String body) {
        for (String p : ESCALATE_REASON_PREFIXES) if (body.startsWith(p)) return true;
        return false;
    }

    /**
     * The decision of a verdict: allow; at least one failing check and EVERY failing check escalate-class -> escalate;
     * otherwise deny. A failing check is escalate-class iff it has at least one reason {@code "<check>: <body>"} and every
     * such body starts with an escalate prefix; a failing check without a reason of its own is a hard failure.
     */
    public static String decisionOf(boolean allow, Map<String, String> checks, List<String> reasons) {
        try {
            if (allow) return ALLOW;
            int failing = 0;
            for (Map.Entry<String, String> e : checks.entrySet()) {
                if (!"fail".equals(e.getValue())) continue;
                failing++;
                String head = e.getKey() + ": ";
                int own = 0;
                for (String r : reasons) {
                    if (r == null || !r.startsWith(head)) continue;
                    own++;
                    if (!escalateBody(r.substring(head.length()))) return DENY;
                }
                if (own == 0) return DENY;
            }
            return failing > 0 ? ESCALATE : DENY;
        } catch (RuntimeException e) {
            return DENY;
        }
    }

    /** {@link #decisionOf(boolean, Map, List)} over a JSON verdict {@code {allow, checks, reasons}}. */
    public static String decisionOf(Map<String, Object> v) {
        try {
            if (Boolean.TRUE.equals(v.get("allow"))) return ALLOW;
            if (!(v.get("checks") instanceof Map)) return DENY;
            Map<String, String> checks = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v.get("checks")).entrySet())
                checks.put((String) e.getKey(), e.getValue() instanceof String ? (String) e.getValue() : "");
            List<String> reasons = new ArrayList<>();
            if (v.get("reasons") instanceof List) for (Object r : (List<?>) v.get("reasons")) if (r instanceof String) reasons.add((String) r);
            return decisionOf(false, checks, reasons);
        } catch (RuntimeException e) {
            return DENY;
        }
    }

    // ---- rule 21: model polarity -------------------------------------------------------------------------------------

    /** Is {@code path} a model-derived env path? {@code singleSource} names the worlds decided by ONE oracle. */
    public static boolean isModelDerivedPath(Object path, List<String> singleSource) {
        if (!(path instanceof String)) return false;
        String[] seg = ((String) path).split("\\.", -1);
        if (!seg[0].equals("env") || seg.length < 2) return false;
        if (MODEL_ENV_ROOTS.contains(seg[1])) return true;
        if (seg[1].equals("world")) return seg.length == 2 ? !singleSource.isEmpty() : singleSource.contains(seg[2]);
        return false;
    }

    private static void collectPaths(Object c, Set<String> out, int depth) {
        if (depth > 64 || !(c instanceof Map)) return;
        Map<?, ?> o = (Map<?, ?>) c;
        for (String k : new String[] {"all_of", "any_of"})
            if (o.get(k) instanceof List) for (Object x : (List<?>) o.get(k)) collectPaths(x, out, depth + 1);
        if (o.containsKey("not")) collectPaths(o.get("not"), out, depth + 1);
        for (String k : new String[] {"field", "ref", "collection"}) if (o.get(k) instanceof String) out.add((String) o.get(k));
    }

    private static void collectWhere(List<?> lists, java.util.function.Predicate<Object> inScope, Set<String> out) {
        for (Object l : lists) {
            if (!(l instanceof List)) continue;
            for (Object p : (List<?>) l) {
                if (inScope != null && !inScope.test(p)) continue;
                Object w = p instanceof Map ? ((Map<?, ?>) p).get("where") : null;
                if (w instanceof List) for (Object c : (List<?>) w) collectPaths(c, out, 0);
            }
        }
    }

    /** Every model-derived env path the predicate lists read, sorted by UTF-8 bytes and de-duplicated. */
    public static List<String> modelPathsRead(List<?> predicateLists, List<String> singleSource) {
        Set<String> found = new HashSet<>();
        collectWhere(predicateLists, null, found);
        List<String> out = new ArrayList<>();
        for (String p : found) if (isModelDerivedPath(p, singleSource)) out.add(p);
        out.sort(Json::compareUtf8);
        return out;
    }

    /** Null = a well-formed {@code tighten} list. JSON {@code null} is refused (omit the member instead). */
    public static String tightenListError(Object t) {
        if (!(t instanceof List)) return "tighten must be an array";
        List<?> l = (List<?>) t;
        if (l.size() > MAX_TIGHTEN_RULES) return "tighten has more than " + MAX_TIGHTEN_RULES + " rules";
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < l.size(); i++) {
            Object x = l.get(i);
            if (!(x instanceof Map)) return "tighten[" + i + "] must be an object";
            @SuppressWarnings("unchecked") Map<String, Object> r = (Map<String, Object>) x;
            String e = IntentArtifacts.closedMembers(r, List.of("id", "when", "signal"), List.of("reason"), "tighten[" + i + "]");
            if (e != null) return e;
            Object id = r.get("id");
            if (!(id instanceof String) || !NAME_RE.matcher((String) id).matches())
                return "tighten[" + i + "].id must match ^[a-z][a-z0-9_]{0,63}$";
            if (!ids.add((String) id)) return "tighten[" + i + "].id '" + id + "' is a duplicate";
            if (!(r.get("when") instanceof Map)) return "tighten[" + i + "].when must be a condition object";
            if (!"escalate".equals(r.get("signal")) && !"deny".equals(r.get("signal")))
                return "tighten[" + i + "].signal must be 'escalate' or 'deny'";
            if (r.containsKey("reason") && (!(r.get("reason") instanceof String) || ((String) r.get("reason")).length() > 256))
                return "tighten[" + i + "].reason must be a string of at most 256 characters";
        }
        return null;
    }

    /** The outcome of rule 21. {@code reason} is null on {@code ok}. */
    public static final class TightenResult {
        public final String outcome;
        public final boolean legacy;
        public final List<String> offending;
        public final String reason;

        TightenResult(String outcome, boolean legacy, List<String> offending, String reason) {
            this.outcome = outcome;
            this.legacy = legacy;
            this.offending = Collections.unmodifiableList(offending);
            this.reason = reason;
        }

        @Override public String toString() { return "TightenResult{" + outcome + ", legacy=" + legacy + ", " + offending + ", " + reason + "}"; }
    }

    private static TightenResult tightenDeny(String why, List<String> offending) { return new TightenResult("deny", false, offending, why); }

    /**
     * Rule 21 over {@code {predicates, tighten, polarity, single_source, context}}. Typing first (a grant-side {@code where}
     * that reads a model-derived path is a refusal unless {@code polarity} is {@code "legacy"}), then the rules in order:
     * {@code when} true -> its signal, unknown -> escalate, false -> no effect; the outcome is the meet of the signals.
     */
    public static TightenResult decideTighten(Map<String, Object> in) {
        try {
            List<String> single = new ArrayList<>();
            if (in.get("single_source") instanceof List) for (Object s : (List<?>) in.get("single_source")) if (s instanceof String) single.add((String) s);
            if (in.containsKey("polarity") && !"legacy".equals(in.get("polarity")))
                return tightenDeny("model_polarity must be 'legacy' when present", List.of());
            if (in.containsKey("tighten")) {
                String le = tightenListError(in.get("tighten"));
                if (le != null) return tightenDeny("malformed tighten list: " + le, List.of());
            }
            List<String> offending = modelPathsRead(in.get("predicates") instanceof List ? (List<?>) in.get("predicates") : List.of(), single);
            boolean legacy = "legacy".equals(in.get("polarity")) && !offending.isEmpty();
            if (!offending.isEmpty() && !legacy)
                return tightenDeny("a grant's where reads model-derived path(s) " + String.join(", ", offending)
                    + ": a model may only tighten (move them into tighten[]) (rule 21)", offending);
            String out = "ok";
            String reason = null;
            @SuppressWarnings("unchecked")
            Map<String, Object> ctx = in.get("context") instanceof Map ? (Map<String, Object>) in.get("context") : new LinkedHashMap<>();
            if (in.get("tighten") instanceof List) {
                for (Object x : (List<?>) in.get("tighten")) {
                    Map<?, ?> r = (Map<?, ?>) x;
                    Predicates.Tri t = Predicates.evaluateConditionTri(r.get("when"), ctx);
                    String sig = null, why = null;
                    if (t == Predicates.Tri.TRUE) {
                        sig = (String) r.get("signal");
                        why = (sig.equals("deny") ? "denied by" : "escalate: asked by") + " tighten rule '" + r.get("id") + "'"
                            + (r.containsKey("reason") ? " (" + r.get("reason") + ")" : "");
                    } else if (t == Predicates.Tri.UNKNOWN) {
                        sig = ESCALATE;
                        why = "escalate: rule '" + r.get("id") + "' could not be decided (a value it reads is missing or ill-typed)";
                    }
                    if (sig != null && rank(signalCeiling(sig)) < rank(signalCeiling(out))) {
                        out = sig;
                        reason = why;
                    }
                }
            }
            return new TightenResult(out, legacy, offending, reason);
        } catch (RuntimeException | StackOverflowError e) {
            return tightenDeny("evaluation error (fail closed): " + e.getClass().getSimpleName(), List.of());
        }
    }

    // ---- rule 20: units ----------------------------------------------------------------------------------------------

    /** Null = well-formed policy unit tags {@code {"action.params.<name>": {kind, currency?, exponent?}}} (closed). */
    public static String unitTagsError(Object u) {
        if (!(u instanceof Map)) return "units must be an object";
        Map<?, ?> m = (Map<?, ?>) u;
        if (m.size() > 64) return "units has more than 64 entries";
        for (String k : jsKeys(m)) {
            Object tv = m.get(k);
            if (!PARAM_PATH_RE.matcher(k).matches()) return "units key '" + k + "' must be an action.params.<name> path";
            if (!(tv instanceof Map)) return "units['" + k + "'] must be an object";
            @SuppressWarnings("unchecked") Map<String, Object> t = (Map<String, Object>) tv;
            String e = IntentArtifacts.closedMembers(t, List.of("kind"), List.of("currency", "exponent"), "units['" + k + "']");
            if (e != null) return e;
            Object kind = t.get("kind");
            if (!(kind instanceof String) || ((String) kind).isEmpty() || ((String) kind).length() > 64)
                return "units['" + k + "'].kind must be a string of 1..64 characters";
            Object cur = t.get("currency");
            if (t.containsKey("currency") && (!(cur instanceof String) || ((String) cur).isEmpty() || ((String) cur).length() > 16))
                return "units['" + k + "'].currency must be a string of 1..16 characters";
            if (t.containsKey("exponent")) {
                Object ex = t.get("exponent");
                if (!(IntentJs.isInt(ex) && IntentJs.num(ex) >= 0 && IntentJs.num(ex) <= 18))
                    return "units['" + k + "'].exponent must be an integer in [0, 18]";
            }
        }
        return null;
    }

    /** The outcome of rule 20. {@code reason} is null when ok. */
    public static final class UnitsResult {
        public final boolean ok;
        public final String reason;
        UnitsResult(boolean ok, String reason) { this.ok = ok; this.reason = reason; }
        @Override public String toString() { return "UnitsResult{" + ok + ", " + reason + "}"; }
    }

    private static String tagText(Map<?, ?> t) {
        if (t == null) return "no unit";
        Object kind = t.get("kind");
        StringBuilder b = new StringBuilder(kind == null ? "?" : IntentRevocation.jsText(kind, true));
        if (t.containsKey("currency")) b.append('/').append(IntentRevocation.jsText(t.get("currency"), true));
        if (t.containsKey("exponent")) b.append("/e").append(IntentJs.isInt(t.get("exponent")) ? Long.toString(IntentJs.lng(t.get("exponent"))) : IntentRevocation.jsText(t.get("exponent"), true));
        return b.toString();
    }

    /** JavaScript {@code a === b} of two possibly-absent members. */
    private static boolean sameMember(Map<?, ?> a, Map<?, ?> b, String k) {
        boolean ha = a.containsKey(k), hb = b.containsKey(k);
        if (ha != hb) return false;
        if (!ha) return true;
        Object x = a.get(k), y = b.get(k);
        Double nx = IntentJs.num(x), ny = IntentJs.num(y);
        if (nx != null || ny != null) return nx != null && ny != null && nx.doubleValue() == ny.doubleValue();
        return x == null ? y == null : x.equals(y);
    }

    private static boolean sameTag(Map<?, ?> a, Map<?, ?> b) {
        return sameMember(a, b, "kind") && sameMember(a, b, "currency") && sameMember(a, b, "exponent");
    }

    private static boolean verbInScope(Object p, String verb) {
        Object v = p instanceof Map ? ((Map<?, ?>) p).get("verb") : null;
        if ("*".equals(v) || verb.equals(v)) return true;
        return v instanceof List && ((List<?>) v).contains(verb);
    }

    /**
     * Rule 20 over {@code {units, schema_units, verb_params, verb, predicates}}: ok iff (1) every policy tag whose parameter
     * the verb declares equals the unit the schema declares for it, and (2) no grant-side {@code where} term in scope of the
     * verb reads a unit-bearing parameter without a tag. Tags for parameters the verb does not declare are ignored.
     */
    public static UnitsResult decideUnits(Map<String, Object> in) {
        try {
            String te = unitTagsError(in.get("units"));
            if (te != null) return new UnitsResult(false, te);
            Map<?, ?> tags = (Map<?, ?>) in.get("units");
            if (!(in.get("verb") instanceof String) || ((String) in.get("verb")).isEmpty()) return new UnitsResult(false, "the verb is missing");
            String verb = (String) in.get("verb");
            Object su = in.containsKey("schema_units") ? in.get("schema_units") : new LinkedHashMap<String, Object>();
            if (!(su instanceof Map)) return new UnitsResult(false, "the schema units table must be an object");
            Map<?, ?> sUnits = (Map<?, ?>) su;
            if (!(in.get("verb_params") instanceof Map)) return new UnitsResult(false, "the schema does not declare verb '" + verb + "'");
            Map<?, ?> params = (Map<?, ?>) in.get("verb_params");

            List<String> names = new ArrayList<>();
            for (Object k : tags.keySet()) names.add((String) k);
            Collections.sort(names);
            for (String path : names) {
                if (!(params.get(path) instanceof Map)) continue;
                Map<?, ?> tag = declaredTag(params, sUnits, path);
                if (tag == null || !sameTag(tag, (Map<?, ?>) tags.get(path)))
                    return new UnitsResult(false, "'" + path + "' is declared as " + tagText(tag) + " by the action schema but the policy term is tagged "
                        + tagText((Map<?, ?>) tags.get(path)) + " (unit confusion)");
            }
            Set<String> read = new HashSet<>();
            collectWhere(in.get("predicates") instanceof List ? (List<?>) in.get("predicates") : List.of(), p -> verbInScope(p, verb), read);
            List<String> sorted = new ArrayList<>(read);
            Collections.sort(sorted);
            for (String path : sorted) {
                if (!PARAM_PATH_RE.matcher(path).matches() || !(params.get(path) instanceof Map)) continue;
                Map<?, ?> tag = declaredTag(params, sUnits, path);
                if (tag != null && !tags.containsKey(path))
                    return new UnitsResult(false, "a policy term reads '" + path + "' (" + tagText(tag) + ") without a unit tag");
            }
            return new UnitsResult(true, null);
        } catch (RuntimeException | StackOverflowError e) {
            return new UnitsResult(false, "evaluation error (fail closed): " + e.getClass().getSimpleName());
        }
    }

    /** The unit tag the schema declares for a verb parameter ({@code params[path].unit} looked up in the units table), or null. */
    private static Map<?, ?> declaredTag(Map<?, ?> params, Map<?, ?> sUnits, String path) {
        Object id = ((Map<?, ?>) params.get(path)).get("unit");
        Object tag = id instanceof String ? sUnits.get(id) : null;
        return tag instanceof Map ? (Map<?, ?>) tag : null;
    }
}
