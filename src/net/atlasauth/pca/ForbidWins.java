package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Forbid-wins decision witness and certificate (security contract C-240, C-241; the reference's {@code forbid-certificate.ts}). A policy is a flat list of
 * clauses: {@code permit} grants (anything undecidable is "not matched"); {@code forbid} vetoes and {@code escalate} caps the decision at escalate, both
 * with the prohibition polarity (anything undecidable is "matched"). The decision is order-independent: any forbid matched denies; else no permit matched
 * denies; else any escalate matched escalates; else allow. {@link #certify} turns a decision into a canonical certificate and {@link #check} re-derives it,
 * so a verifier never trusts a certificate it did not recompute. Pure and total.
 */
public final class ForbidWins {
    private ForbidWins() {}

    public static final int CERT_VERSION = 1;
    public static final String CERT_KIND = "forbid-wins";
    public static final int MAX_CLAUSES = 512;
    private static final List<String> KINDS = Arrays.asList("permit", "forbid", "escalate");
    private static final Set<String> OPS = new HashSet<>(Arrays.asList("eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of"));
    private static final int MAX_CONDITION_DEPTH = 32;

    // ---- the veto-polarity trigger (prohibitions.ts whenMatches)

    private static boolean isObj(Object o) { return o instanceof Map; }

    static String validateCondition(Object c, int depth) {
        if (!isObj(c)) return "condition not an object";
        Map<?, ?> m = (Map<?, ?>) c;
        if (depth > MAX_CONDITION_DEPTH) return "condition nesting too deep";
        if (m.containsKey("all_of") || m.containsKey("any_of") || m.containsKey("not")) {
            if (m.containsKey("not")) return validateCondition(m.get("not"), depth + 1);
            String key = m.containsKey("all_of") ? "all_of" : "any_of";
            Object arr = m.get(key);
            if (!(arr instanceof List) || ((List<?>) arr).isEmpty()) return "condition." + key + " must be a non-empty array";
            for (Object child : (List<?>) arr) {
                String e = validateCondition(child, depth + 1);
                if (e != null) return e;
            }
            return null;
        }
        if (!(m.get("field") instanceof String) || ((String) m.get("field")).isEmpty()) return "condition.field missing";
        if (!(m.get("op") instanceof String) || !OPS.contains(m.get("op"))) return "unknown condition op " + IntentRevocation.jsText(m.get("op"), m.containsKey("op"));
        if (m.containsKey("ref") && (!(m.get("ref") instanceof String) || ((String) m.get("ref")).isEmpty())) return "bad condition.ref";
        if ("member_of".equals(m.get("op")) && m.containsKey("collection") && (!(m.get("collection") instanceof String) || ((String) m.get("collection")).isEmpty())) return "bad condition.collection";
        return null;
    }

    /** Null when a trigger ({@code {verb, resource?, where?}}) is well formed. */
    static String validateWhen(Object w, String label) {
        if (!isObj(w)) return label + ": not an object";
        Map<?, ?> m = (Map<?, ?>) w;
        Object v = m.get("verb");
        boolean verbOk = (v instanceof String && !((String) v).isEmpty()) || (v instanceof List && !((List<?>) v).isEmpty() && allNonEmptyStrings((List<?>) v));
        if (!verbOk) return label + ": bad verb";
        if (m.containsKey("resource")) {
            Object r = m.get("resource");
            if (!(r instanceof String)) return label + ": bad resource";
            if (((String) r).startsWith("re:")) {
                String src = ((String) r).substring(3);
                if (src.length() > 200 || !SafeRegex.isSafeSource(src)) return label + ": unsafe regex resource";
                if (SafeRegex.compile(src) == null) return label + ": invalid regex resource";
            }
        }
        if (m.containsKey("where")) {
            if (!(m.get("where") instanceof List)) return label + ": where not an array";
            for (Object c : (List<?>) m.get("where")) {
                String e = validateCondition(c, 0);
                if (e != null) return label + ": " + e;
            }
        }
        return null;
    }

    private static boolean allNonEmptyStrings(List<?> l) {
        for (Object x : l) if (!(x instanceof String) || ((String) x).isEmpty()) return false;
        return true;
    }

    /**
     * Does a prohibition trigger match? verb and resource exactly as the permission DSL; where-conditions conservatively. FULLY fail-closed: a malformed
     * trigger, an unsafe regex, an oversized regex subject, an unknown op, a missing field or operand all count as MATCHED (the veto applies). Never throws.
     */
    @SuppressWarnings("unchecked")
    public static boolean whenMatches(Object w, Map<String, Object> ctx) {
        try {
            if (validateWhen(w, "when") != null) return true;
            Map<String, Object> a = ctx == null || !(ctx.get("action") instanceof Map) ? null : (Map<String, Object>) ctx.get("action");
            if (a == null || !(a.get("verb") instanceof String) || !(a.get("resource") instanceof String)) return true;
            Map<String, Object> wm = (Map<String, Object>) w;
            Object res = wm.get("resource");
            boolean oversized = res instanceof String && ((String) res).startsWith("re:") && ((String) a.get("resource")).length() > Predicates.MAX_RE_RESOURCE_LEN;
            int refused0 = SafeRegex.refusals();
            Map<String, Object> probe = new LinkedHashMap<>();
            probe.put("verb", wm.get("verb"));
            if (!oversized && res != null) probe.put("resource", res);
            if (!Predicates.predicateMatches(probe, ctx)) {
                if (SafeRegex.refusals() == refused0) return false;
            }
            if (wm.get("where") instanceof List) {
                for (Object c : (List<?>) wm.get("where")) if (Predicates.evaluateConditionTri(c, ctx) == Predicates.Tri.FALSE) return false;
            }
            return true;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return true; // cannot evaluate: the veto applies
        }
    }

    // ---- clauses

    /** Null when the clause list is well formed (distinct ids, known kinds, a predicate for each). */
    public static String clausesError(Object clauses) {
        if (!(clauses instanceof List)) return "clauses must be an array";
        List<?> l = (List<?>) clauses;
        if (l.size() > MAX_CLAUSES) return "more than " + MAX_CLAUSES + " clauses";
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < l.size(); i++) {
            Object c = l.get(i);
            if (!isObj(c)) return "clauses[" + i + "] must be an object";
            Map<?, ?> m = (Map<?, ?>) c;
            Object id = m.get("id");
            if (!(id instanceof String) || ((String) id).isEmpty() || ((String) id).length() > 128) return "clauses[" + i + "].id must be a string of 1..128 characters";
            if (!seen.add((String) id)) return "clauses[" + i + "].id '" + id + "' is a duplicate";
            if (!(m.get("kind") instanceof String) || !KINDS.contains(m.get("kind"))) return "clauses[" + i + "].kind must be permit, forbid or escalate";
            if (m.containsKey("signer") && (!(m.get("signer") instanceof String) || ((String) m.get("signer")).length() > 256)) return "clauses[" + i + "].signer must be a string of at most 256 characters";
            if (!isObj(m.get("when"))) return "clauses[" + i + "].when must be a predicate object";
        }
        return null;
    }

    private static String valueOf(Map<?, ?> c, Map<String, Object> ctx) {
        Object when = c.get("when");
        if ("permit".equals(c.get("kind"))) return Predicates.predicateMatches(when, ctx) ? "true" : "false";
        if (!whenMatches(when, ctx)) return "false";
        return Predicates.predicateMatches(when, ctx) ? "true" : "unknown";
    }

    private static int rank(String signer, List<String> precedence) {
        int i = signer == null ? -1 : precedence.indexOf(signer);
        return i < 0 ? precedence.size() : i;
    }

    /** A decision: {@code decision} allow, escalate or deny; the winner (kind, id), the shadowed ids and the per-clause values. */
    public static final class Decision {
        public final String decision, winnerKind, winnerId;
        public final List<String> shadowed;
        public final List<Map<String, Object>> values;

        Decision(String decision, String winnerKind, String winnerId, List<String> shadowed, List<Map<String, Object>> values) {
            this.decision = decision; this.winnerKind = winnerKind; this.winnerId = winnerId; this.shadowed = shadowed; this.values = values;
        }
    }

    private static Decision malformed() { return new Decision("deny", "malformed", null, new ArrayList<>(), new ArrayList<>()); }

    /** Decide a clause list against an action context {@code {action: {verb, resource, params}}}. {@code precedence} lists signers most authoritative first; {@code permitSigners} (nullable) drops other signers' permits. */
    @SuppressWarnings("unchecked")
    public static Decision decide(Object clauses, Map<String, Object> ctx, List<String> precedence, List<String> permitSigners) {
        try {
            if (clausesError(clauses) != null) return malformed();
            Object a = ctx == null ? null : ctx.get("action");
            if (!(a instanceof Map) || !(((Map<?, ?>) a).get("verb") instanceof String) || !(((Map<?, ?>) a).get("resource") instanceof String)) return malformed();
            List<String> prec = precedence == null ? new ArrayList<>() : precedence;
            List<Map<String, Object>> cs = new ArrayList<>();
            for (Object c : (List<?>) clauses) cs.add((Map<String, Object>) c);
            List<Map<String, Object>> values = new ArrayList<>();
            for (Map<String, Object> c : cs) {
                boolean active = !"permit".equals(c.get("kind")) || permitSigners == null || (c.get("signer") instanceof String && permitSigners.contains(c.get("signer")));
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("id", c.get("id"));
                v.put("kind", c.get("kind"));
                v.put("value", active ? valueOf(c, ctx) : "false");
                values.add(v);
            }
            List<Map<String, Object>> forbids = hit(cs, values, "forbid");
            forbids.sort(Comparator.<Map<String, Object>>comparingInt(c -> rank((String) c.get("signer"), prec)).thenComparing(c -> (String) c.get("id"), String::compareTo));
            List<Map<String, Object>> permits = hit(cs, values, "permit");
            List<Map<String, Object>> escalates = hit(cs, values, "escalate");
            if (!forbids.isEmpty()) return new Decision("deny", "forbid", (String) forbids.get(0).get("id"), others(forbids, permits, escalates, forbids.get(0)), values);
            if (permits.isEmpty()) return new Decision("deny", "none", null, others(forbids, permits, escalates, null), values);
            if (!escalates.isEmpty()) return new Decision("escalate", "escalate", (String) escalates.get(0).get("id"), others(forbids, permits, escalates, escalates.get(0)), values);
            return new Decision("allow", "permit", (String) permits.get(0).get("id"), others(forbids, permits, escalates, permits.get(0)), values);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return malformed();
        }
    }

    private static List<Map<String, Object>> hit(List<Map<String, Object>> cs, List<Map<String, Object>> values, String kind) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < cs.size(); i++) if (kind.equals(cs.get(i).get("kind")) && !"false".equals(values.get(i).get("value"))) out.add(cs.get(i));
        return out;
    }

    private static List<String> others(List<Map<String, Object>> f, List<Map<String, Object>> p, List<Map<String, Object>> e, Map<String, Object> win) {
        List<String> out = new ArrayList<>();
        for (List<Map<String, Object>> l : Arrays.asList(f, p, e)) for (Map<String, Object> c : l) if (c != win) out.add((String) c.get("id"));
        return out;
    }

    /** The canonical certificate of a decision. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> certify(Object clauses, Map<String, Object> ctx, List<String> precedence, List<String> permitSigners) {
        Decision d = decide(clauses, ctx, precedence, permitSigners);
        Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
        if (clauses instanceof List) for (Object c : (List<?>) clauses) if (c instanceof Map && ((Map<?, ?>) c).get("id") instanceof String) byId.put((String) ((Map<?, ?>) c).get("id"), (Map<String, Object>) c);
        Map<String, Object> cert = new LinkedHashMap<>();
        cert.put("v", IntentJs.ofLong(CERT_VERSION));
        cert.put("kind", CERT_KIND);
        cert.put("policy", Pca.hashCanonical(clauses));
        cert.put("action", Pca.hashCanonical(ctx));
        cert.put("decision", d.decision);
        Map<String, Object> winner = new LinkedHashMap<>();
        winner.put("kind", d.winnerKind);
        winner.put("id", d.winnerId);
        cert.put("winner", winner);
        cert.put("shadowed", new ArrayList<Object>(d.shadowed));
        List<Object> rows = new ArrayList<>();
        for (Map<String, Object> v : d.values) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", v.get("id"));
            row.put("kind", v.get("kind"));
            Map<String, Object> src = byId.get(v.get("id"));
            if (src != null && src.get("signer") != null) row.put("signer", src.get("signer"));
            row.put("value", v.get("value"));
            rows.add(row);
        }
        cert.put("clauses", rows);
        return cert;
    }

    /** The rule over the certificate's own table: the decision, winner and shadowed list the per-clause values force (no evaluator needed). */
    @SuppressWarnings("unchecked")
    public static boolean consistent(Object cert, List<String> precedence) {
        try {
            if (!(cert instanceof Map)) return false;
            Map<String, Object> c = (Map<String, Object>) cert;
            if (!IntentJs.isInt(c.get("v")) || IntentJs.num(c.get("v")) != CERT_VERSION || !CERT_KIND.equals(c.get("kind")) || !(c.get("clauses") instanceof List)) return false;
            List<Map<String, Object>> rows = new ArrayList<>();
            for (Object r : (List<?>) c.get("clauses")) { if (!(r instanceof Map)) return false; rows.add((Map<String, Object>) r); }
            Map<String, Object> w = c.get("winner") instanceof Map ? (Map<String, Object>) c.get("winner") : null;
            List<Object> shadowed = c.get("shadowed") instanceof List ? (List<Object>) c.get("shadowed") : null;
            if (w != null && "malformed".equals(w.get("kind"))) return rows.isEmpty() && "deny".equals(c.get("decision")) && w.get("id") == null && shadowed != null && shadowed.isEmpty();
            List<String> prec = precedence == null ? new ArrayList<>() : precedence;
            for (Map<String, Object> r : rows) if (!KINDS.contains(r.get("kind")) || !Arrays.asList("true", "false", "unknown").contains(r.get("value"))) return false;
            List<Map<String, Object>> forbids = new ArrayList<>(), permits = new ArrayList<>(), escalates = new ArrayList<>();
            for (Map<String, Object> r : rows) {
                if ("false".equals(r.get("value"))) continue;
                (r.get("kind").equals("forbid") ? forbids : r.get("kind").equals("permit") ? permits : escalates).add(r);
            }
            forbids.sort(Comparator.<Map<String, Object>>comparingInt(r -> rank((String) r.get("signer"), prec)).thenComparing(r -> (String) r.get("id"), String::compareTo));
            Map<String, Object> win = !forbids.isEmpty() ? forbids.get(0) : permits.isEmpty() ? null : !escalates.isEmpty() ? escalates.get(0) : permits.get(0);
            String decision = !forbids.isEmpty() ? "deny" : permits.isEmpty() ? "deny" : !escalates.isEmpty() ? "escalate" : "allow";
            String kind = !forbids.isEmpty() ? "forbid" : permits.isEmpty() ? "none" : !escalates.isEmpty() ? "escalate" : "permit";
            List<Object> want = new ArrayList<>(others(forbids, permits, escalates, win));
            return w != null && decision.equals(c.get("decision")) && kind.equals(w.get("kind")) && java.util.Objects.equals(win == null ? null : win.get("id"), w.get("id"))
                && shadowed != null && Json.canonicalize(want).equals(Json.canonicalize(shadowed));
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return false;
        }
    }

    /** Recompute the certificate from the clauses and the action; it must match byte for byte. Null when it does, else the refusal reason. */
    public static String check(Object cert, Object clauses, Map<String, Object> ctx, List<String> precedence, List<String> permitSigners) {
        try {
            if (clausesError(clauses) != null) return "malformed clauses";
            if (!consistent(cert, precedence)) return "certificate table does not entail its decision";
            Map<String, Object> again = certify(clauses, ctx, precedence, permitSigners);
            if (!Pca.hashCanonical(again).equals(Pca.hashCanonical(cert))) return "certificate does not match the recomputed decision";
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return "certificate check error (fail closed)";
        }
    }
}
