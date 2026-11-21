package net.atlasauth.pca;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * Agent-native authority primitives (the TypeScript {@code agent-native} module): uncertainty attestation, rationale binding,
 * the semantic firewall, capability introspection and authority leases. Pure and deterministic: no clocks (callers pass
 * {@code now}), no randomness except the default rationale salt. The verifying and evaluating functions are total and fail
 * closed; only the authoring helpers ({@code bindRationale}, {@code toolSchemaCaveat}, {@code grantLease}, {@code predicatesCaveat})
 * throw {@link IllegalArgumentException}. Values are JSON trees (maps, lists, strings, numbers, booleans, null), the same shape as
 * the reference, so artefacts round-trip with every other implementation. {@code signCaution} / {@code signHeartbeat} live in
 * {@link SignersMore}, {@code validateArgSchema} / {@code evaluateToolSchema} in {@link Authorize}.
 *
 * <p>{@link #renewCapabilityLease} is the reference's pure {@code renewLease(lease, heartbeat, now)}; the grants registry keeps its
 * own {@code renewLease} in {@link Lease}.
 */
public final class AgentNative {
    private AgentNative() {}

    // ---- constants ---------------------------------------------------------------------------------------------------------

    public static final String CAVEAT_ENVELOPE = "envelope";
    public static final String CAVEAT_EXPIRES = "expires";
    public static final String CAVEAT_NOT_BEFORE = "not_before";
    public static final String CAVEAT_RATE = "rate";
    public static final String CAVEAT_MAX_BLAST_RADIUS = "max_blast_radius";
    public static final String CAVEAT_REVERSIBILITY_MAX = "reversibility_max";
    public static final String CAVEAT_DELEGATION_DEPTH = "delegation_depth";
    public static final String CAVEAT_PREDICATES = "predicates";
    public static final String CAVEAT_TOOL_SCHEMA = "tool_schema";
    public static final String CAVEAT_MAX_SPEND = "max_spend";
    public static final int MAX_CAUTION_REASON_LEN = SignersMore.MAX_CAUTION_REASON_LEN;
    public static final int MIN_SALT_BYTES = 16;
    public static final int MIN_SALT_DISTINCT_BYTES = 8;
    public static final int MAX_RATIONALE_LEN = 8192;
    public static final int MAX_SCHEMA_DEPTH = Authorize.MAX_SCHEMA_DEPTH;
    public static final int MAX_SCHEMA_NODES = Authorize.MAX_SCHEMA_NODES;
    public static final int MAX_OBJECT_PROPS = Authorize.MAX_OBJECT_PROPS;
    public static final int MAX_ENUM_VALUES = Authorize.MAX_ENUM_VALUES;
    public static final int DEFAULT_MAX_ARRAY_ITEMS = Authorize.DEFAULT_MAX_ARRAY_ITEMS;
    public static final int ABSOLUTE_MAX_ARRAY_ITEMS = Authorize.ABSOLUTE_MAX_ARRAY_ITEMS;
    public static final int DEFAULT_MAX_STRING_LEN = Authorize.DEFAULT_MAX_STRING_LEN;
    public static final int ABSOLUTE_MAX_STRING_LEN = Authorize.ABSOLUTE_MAX_STRING_LEN;
    public static final int MAX_VALUE_NODES = Authorize.MAX_VALUE_NODES;
    /** Max tolerated skew between a heartbeat's {@code at} (or the clock vs the last renewal) and server {@code now}. */
    public static final long HEARTBEAT_SKEW_MS = 30_000L;
    /** Longest lease ttl accepted (7 days). */
    public static final long MAX_LEASE_TTL_MS = 7L * 24 * 3_600_000L;

    /** Every constant above by its reference name (the corpus {@code constants} case). */
    public static Map<String, Object> constants() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("CAVEAT_ENVELOPE", CAVEAT_ENVELOPE);
        m.put("CAVEAT_EXPIRES", CAVEAT_EXPIRES);
        m.put("CAVEAT_NOT_BEFORE", CAVEAT_NOT_BEFORE);
        m.put("CAVEAT_RATE", CAVEAT_RATE);
        m.put("CAVEAT_MAX_BLAST_RADIUS", CAVEAT_MAX_BLAST_RADIUS);
        m.put("CAVEAT_REVERSIBILITY_MAX", CAVEAT_REVERSIBILITY_MAX);
        m.put("CAVEAT_DELEGATION_DEPTH", CAVEAT_DELEGATION_DEPTH);
        m.put("CAVEAT_PREDICATES", CAVEAT_PREDICATES);
        m.put("CAVEAT_TOOL_SCHEMA", CAVEAT_TOOL_SCHEMA);
        m.put("CAVEAT_MAX_SPEND", CAVEAT_MAX_SPEND);
        m.put("MAX_CAUTION_REASON_LEN", MAX_CAUTION_REASON_LEN);
        m.put("MIN_SALT_BYTES", MIN_SALT_BYTES);
        m.put("MIN_SALT_DISTINCT_BYTES", MIN_SALT_DISTINCT_BYTES);
        m.put("MAX_RATIONALE_LEN", MAX_RATIONALE_LEN);
        m.put("MAX_SCHEMA_DEPTH", MAX_SCHEMA_DEPTH);
        m.put("MAX_SCHEMA_NODES", MAX_SCHEMA_NODES);
        m.put("MAX_OBJECT_PROPS", MAX_OBJECT_PROPS);
        m.put("MAX_ENUM_VALUES", MAX_ENUM_VALUES);
        m.put("DEFAULT_MAX_ARRAY_ITEMS", DEFAULT_MAX_ARRAY_ITEMS);
        m.put("ABSOLUTE_MAX_ARRAY_ITEMS", ABSOLUTE_MAX_ARRAY_ITEMS);
        m.put("DEFAULT_MAX_STRING_LEN", DEFAULT_MAX_STRING_LEN);
        m.put("ABSOLUTE_MAX_STRING_LEN", ABSOLUTE_MAX_STRING_LEN);
        m.put("MAX_VALUE_NODES", MAX_VALUE_NODES);
        m.put("HEARTBEAT_SKEW_MS", HEARTBEAT_SKEW_MS);
        m.put("MAX_LEASE_TTL_MS", MAX_LEASE_TTL_MS);
        return m;
    }

    // ---- helpers -----------------------------------------------------------------------------------------------------------

    private static Double fin(Object o) { return Caveats.fin(o); }

    private static boolean nonEmpty(Object x) { return x instanceof String && !((String) x).isEmpty(); }

    private static byte[] msgOf(String domain, Object body) { return Pca.canonBytes(Issue.obj("d", domain, "b", body)); }

    private static double clamp01(double x) { return Math.min(1, Math.max(0, x)); }

    /** {@code Number.isInteger(x)} on a JSON value (a non-number is false). */
    private static boolean isInteger(Object o) {
        Double d = IntentJs.num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.floor(d);
    }

    private static boolean isNonNegInteger(Object o) { return isInteger(o) && IntentJs.num(o) >= 0 && !IntentJs.isNegZero(IntentJs.num(o)); }

    private static Object cloneLenient(Object x) { return Json.parseLenient(Json.canonicalize(x)); }

    private static String hash(Object v) { return Pca.hashCanonical(v); }

    // ======================================================================================================================
    // 1. Uncertainty attestation (monotone self-escalation)
    // ======================================================================================================================

    private static final List<String> CAUTION_KEYS = List.of("action_digest", "caution", "reason", "holder", "sig");

    /**
     * Verify a caution claim: strict shape (no smuggled member), caution in [0,1], a valid signature by {@code claim.holder}, bound to
     * {@code expectedActionDigest} (when given, i.e. not null) and signed by {@code expectedHolder} (when given). Total.
     */
    public static boolean verifyCaution(Object claim, Object expectedActionDigest, Object expectedHolder) {
        return verifyCautionImpl(claim, expectedActionDigest != null, expectedActionDigest, expectedHolder != null, expectedHolder);
    }

    private static boolean verifyCautionImpl(Object claimO, boolean hasDigest, Object digest, boolean hasHolder, Object holder) {
        try {
            if (!(claimO instanceof Map)) return false;
            Map<?, ?> claim = (Map<?, ?>) claimO;
            if (!(claim.get("sig") instanceof String)) return false;
            for (Object k : claim.keySet()) if (!CAUTION_KEYS.contains(k)) return false;
            if (SignersMore.cautionBodyError(claim) != null) return false;
            if (hasDigest && !Objects.equals(claim.get("action_digest"), digest)) return false;
            if (hasHolder && !Objects.equals(claim.get("holder"), holder)) return false;
            Map<String, Object> body = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : claim.entrySet()) if (!"sig".equals(e.getKey())) body.put((String) e.getKey(), e.getValue());
            return Pca.verifyB64u((String) claim.get("holder"), msgOf("atlas-pca/caution/v1", body), (String) claim.get("sig"));
        } catch (RuntimeException | StackOverflowError e) {
            return false;
        }
    }

    /**
     * {@code max(agentDeclaredCaution, serverRisk)}: always at least {@code serverRisk} (clamped to [0,1]) and non-decreasing in the
     * declared value. An unusable declaration (null, NaN, an infinity, a non-number) is ignored; an unusable {@code serverRisk}
     * fails closed to 1.
     */
    public static double combineCaution(Object agentDeclaredCaution, Object serverRisk) {
        Double sv = fin(serverRisk);
        double s = sv == null ? 1 : clamp01(sv);
        Double d = fin(agentDeclaredCaution);
        if (d == null) return s;
        return Math.max(clamp01(d), s);
    }

    /**
     * As {@link #combineCaution} for a signed claim: only a valid claim bound to THIS action (and, when {@code expectedHolder} is not
     * null, to THIS holder) is honoured. Returns {@code {effectiveRisk, honoured, escalated}}.
     */
    public static Map<String, Object> combineSignedCaution(Object claim, Object actionDigest, Object serverRisk, Object expectedHolder) {
        Double sv = fin(serverRisk);
        double s = sv == null ? 1 : clamp01(sv);
        boolean ok = claim != null && verifyCautionImpl(claim, true, actionDigest, expectedHolder != null, expectedHolder);
        double eff = combineCaution(ok ? ((Map<?, ?>) claim).get("caution") : null, s);
        return Issue.obj("effectiveRisk", eff, "honoured", ok, "escalated", eff > s);
    }

    /** Exhaustive-grid check of the monotonicity property: {@code {ok: true}}, or {@code {ok: false, counterexample: [d, s]}}. */
    public static Map<String, Object> checkCautionMonotone(Object grid) {
        if (!(grid instanceof List)) throw new IllegalArgumentException("checkCautionMonotone: grid must be an array");
        List<Double> g = new ArrayList<>();
        for (Object x : (List<?>) grid) { Double f = fin(x); if (f != null) g.add(f); }
        for (double s : g) {
            for (double d : g) {
                double e = combineCaution(d, s);
                if (e < clamp01(s)) return cx(d, s);
                for (double d2 : g) if (d2 >= d && combineCaution(d2, s) < e) return cx(d2, s);
            }
        }
        return Issue.obj("ok", true);
    }

    private static Map<String, Object> cx(double a, double b) {
        List<Object> l = new ArrayList<>();
        l.add(a);
        l.add(b);
        return Issue.obj("ok", false, "counterexample", l);
    }

    // ======================================================================================================================
    // 2. Rationale binding (commit / reveal)
    // ======================================================================================================================

    /**
     * Entropy floor of a commitment salt: base64url (no padding, canonical) that decodes to at least 16 bytes with at least 8 distinct
     * byte values, at most 256 characters.
     */
    public static boolean isStrongSalt(Object salt) {
        if (!(salt instanceof String)) return false;
        String s = (String) salt;
        if (s.isEmpty() || s.length() > 256) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
        }
        byte[] b = Pca.decodeB64uStrict(s, -1);
        if (b == null || b.length < MIN_SALT_BYTES) return false;
        Set<Byte> distinct = new HashSet<>();
        for (byte x : b) distinct.add(x);
        return distinct.size() >= MIN_SALT_DISTINCT_BYTES;
    }

    private static String commitDigest(String actionDigest, Object salt, String rationale) {
        return hash(Issue.obj("d", "atlas-pca/rationale/v1", "a", actionDigest, "s", salt, "r", rationale));
    }

    /** {@link #bindRationale(Object, Object, Object)} with a fresh 32-byte random salt. */
    public static Map<String, Object> bindRationale(Object action, Object rationale) {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return bindRationale(action, rationale, Pca.b64(b));
    }

    /**
     * The agent commits to its stated reason: returns {@code {commitment: {v, action_digest, commitment}, reveal: {rationale, salt}}}.
     * Publish the commitment, KEEP the reveal. Throws on a non-string or oversized rationale, a weak salt ({@link #isStrongSalt}) or a
     * non-canonicalizable action.
     */
    public static Map<String, Object> bindRationale(Object action, Object rationale, Object salt) {
        if (!(rationale instanceof String)) throw new IllegalArgumentException("bindRationale: rationale must be a string");
        String r = (String) rationale;
        if (r.length() > MAX_RATIONALE_LEN) throw new IllegalArgumentException("bindRationale: rationale too long");
        if (!isStrongSalt(salt)) throw new IllegalArgumentException("bindRationale: salt must be b64u of >=" + MIN_SALT_BYTES + " bytes with >=" + MIN_SALT_DISTINCT_BYTES + " distinct values");
        String ad = hash(action);
        return Issue.obj("commitment", Issue.obj("v", 1L, "action_digest", ad, "commitment", commitDigest(ad, salt, r)),
            "reveal", Issue.obj("rationale", r, "salt", salt));
    }

    private static boolean isOne(Object v) { Double d = v instanceof Json.Num || v instanceof Number ? IntentJs.num(v) : null; return d != null && d == 1.0; }

    /** Does the revealed rationale open the commitment? A reveal with a weak salt is rejected even if it hashes correctly. Total. */
    public static boolean verifyRationale(Object commitment, Object reveal) { return verifyRationaleImpl(commitment, reveal, false, null); }

    /** As {@link #verifyRationale(Object, Object)}, additionally requiring the commitment to be for this very {@code action}. */
    public static boolean verifyRationale(Object commitment, Object reveal, Object action) { return verifyRationaleImpl(commitment, reveal, true, action); }

    private static boolean verifyRationaleImpl(Object commitment, Object reveal, boolean hasAction, Object action) {
        try {
            if (!(commitment instanceof Map) || !(reveal instanceof Map)) return false;
            Map<?, ?> c = (Map<?, ?>) commitment, r = (Map<?, ?>) reveal;
            if (!isOne(c.get("v")) || !nonEmpty(c.get("action_digest")) || !nonEmpty(c.get("commitment"))) return false;
            Object rat = r.get("rationale");
            if (!(rat instanceof String) || ((String) rat).length() > MAX_RATIONALE_LEN || !isStrongSalt(r.get("salt"))) return false;
            if (hasAction && !hash(action).equals(c.get("action_digest"))) return false;
            return commitDigest((String) c.get("action_digest"), r.get("salt"), (String) rat).equals(c.get("commitment"));
        } catch (RuntimeException | StackOverflowError e) {
            return false;
        }
    }

    private static Map<String, Object> audit(String verdict, boolean slashable, Map<String, Object> evidence) {
        return Issue.obj("verdict", verdict, "slashable", slashable, "evidence", evidence);
    }

    /**
     * After-the-fact audit. {@code judge} returns exactly {@code Boolean.TRUE} for a consistent rationale (anything else is a false
     * one); a throwing judge is {@code judge_error}. {@code reveal} may be null (never opened). Returns
     * {@code {verdict, slashable, evidence}}; {@code malformed}, {@code wrong_action} and {@code judge_error} are never slashable.
     * Total.
     */
    public static Map<String, Object> auditRationale(Object commitment, Object action, Object reveal, BiFunction<String, Object, Object> judge) {
        Map<?, ?> cm = commitment instanceof Map ? (Map<?, ?>) commitment : null;
        Map<String, Object> evidence = Issue.obj("commitment", cm != null && cm.get("commitment") instanceof String ? cm.get("commitment") : "",
            "action_digest", cm != null && cm.get("action_digest") instanceof String ? cm.get("action_digest") : "");
        try {
            if (cm == null || !isOne(cm.get("v")) || !nonEmpty(cm.get("action_digest")) || !nonEmpty(cm.get("commitment"))) return audit("malformed", false, evidence);
            if (!hash(action).equals(cm.get("action_digest"))) return audit("wrong_action", false, evidence);
            if (reveal == null || !verifyRationaleImpl(commitment, reveal, true, action)) return audit("unopened", true, evidence);
            String rationale = (String) ((Map<?, ?>) reveal).get("rationale");
            Map<String, Object> opened = new LinkedHashMap<>(evidence);
            opened.put("rationale", rationale);
            boolean ok;
            try {
                ok = Boolean.TRUE.equals(judge.apply(rationale, action));
            } catch (RuntimeException | StackOverflowError e) {
                return audit("judge_error", false, opened);
            }
            return audit(ok ? "consistent" : "false_rationale", !ok, opened);
        } catch (RuntimeException | StackOverflowError e) {
            return audit("malformed", false, evidence);
        }
    }

    // ======================================================================================================================
    // 3. Semantic firewall
    // ======================================================================================================================

    private static String bindingOf(Object tool, Object signatureDigest, Object schema) {
        return hash(Issue.obj("tool", tool, "signature_digest", signatureDigest, "schema", schema));
    }

    /**
     * Build a {@code tool_schema} caveat for one tool: authority exists only for that exact tool, signature and (nested) argument schema.
     * Throws when the signature names no tool, the schema is invalid ({@link Authorize#validateArgSchema}) or anything is not
     * canonicalizable. The schema is deep-cloned in canonical form.
     */
    public static Map<String, Object> toolSchemaCaveat(Object toolSignature, Object argSchema) {
        String tool = toolSignature instanceof String ? (String) toolSignature
            : toolSignature instanceof Map && ((Map<?, ?>) toolSignature).get("name") instanceof String ? (String) ((Map<?, ?>) toolSignature).get("name") : "";
        if (tool.isEmpty()) throw new IllegalArgumentException("toolSchemaCaveat: tool name required");
        String err = Authorize.validateArgSchema(argSchema);
        if (err != null) throw new IllegalArgumentException("toolSchemaCaveat: " + err);
        Object schema = cloneLenient(argSchema);
        String sig = hash(toolSignature);
        return Issue.obj("type", CAVEAT_TOOL_SCHEMA, "tool", tool, "signature_digest", sig, "schema", schema,
            "schema_digest", hash(schema), "binding_digest", bindingOf(tool, sig, schema));
    }

    /** Evaluator for a {@code tool_schema} caveat; {@code ctx = {toolCall}}. Anything else is unsatisfied. */
    public static boolean toolSchemaEvaluator(Object caveat, Object ctx) {
        if (!(ctx instanceof Map) || !(((Map<?, ?>) ctx).get("toolCall") instanceof Map)) return false;
        return Authorize.evaluateToolSchema(caveat, ((Map<?, ?>) ctx).get("toolCall")).ok;
    }

    /** The delegated-narrowing caveat {@code {type: "predicates", allow}} (deep-cloned canonical form; throws on a non-finite number). */
    public static Map<String, Object> predicatesCaveat(Object allow) {
        return Issue.obj("type", CAVEAT_PREDICATES, "allow", cloneLenient(allow));
    }

    /**
     * The action's spend in USD as {@code max_spend} reads it: an own {@code action.action.params.amount} (finite, &gt;= 0) with an own
     * {@code currency}, when present, of "usd" / "USD". Null when there is no readable spend.
     */
    public static Double actionSpendUsd(Object action) {
        if (!(action instanceof Map)) return null;
        Object act = ((Map<?, ?>) action).get("action");
        if (!(act instanceof Map)) return null;
        Object params = ((Map<?, ?>) act).get("params");
        if (!(params instanceof Map) || !((Map<?, ?>) params).containsKey("amount")) return null;
        Map<?, ?> p = (Map<?, ?>) params;
        Double amount = fin(p.get("amount"));
        if (amount == null || amount < 0) return null;
        if (p.containsKey("currency") && !"usd".equals(p.get("currency")) && !"USD".equals(p.get("currency"))) return null;
        return amount;
    }

    /**
     * Superset of the stock caveat evaluator: adds {@code predicates} (needs {@code ctx.action}), {@code max_spend} (needs
     * {@code ctx.action}) and {@code tool_schema} (needs {@code ctx.toolCall}); anything else defers to the stock evaluator (unknown
     * types fail closed). Total.
     */
    public static boolean agentNativeCaveatEvaluator(Object caveat, Object ctx) {
        try {
            if (!(caveat instanceof Map) || !(ctx instanceof Map)) return false;
            Map<?, ?> cv = (Map<?, ?>) caveat, c = (Map<?, ?>) ctx;
            Object t = cv.get("type");
            if (CAVEAT_TOOL_SCHEMA.equals(t)) return toolSchemaEvaluator(cv, c);
            if (CAVEAT_PREDICATES.equals(t)) {
                Object a = c.get("action");
                if (!(a instanceof Map) || !(cv.get("allow") instanceof List)) return false;
                @SuppressWarnings("unchecked") Map<String, Object> am = (Map<String, Object>) a;
                for (Object p : (List<?>) cv.get("allow")) if (Predicates.predicateMatches(p, am)) return true;
                return false;
            }
            if (CAVEAT_MAX_SPEND.equals(t)) {
                Double lim = fin(cv.get("usd"));
                Double spend = actionSpendUsd(c.get("action"));
                return lim != null && spend != null && spend <= lim;
            }
            // the stock evaluator reads the camelCase context members; Caveats takes the same data under its snake_case names
            Map<String, Object> sc = new LinkedHashMap<>();
            String[][] names = {{"now", "now"}, {"blastRadius", "blast_radius"}, {"reversibilityClass", "reversibility_class"}, {"delegationDepth", "delegation_depth"}, {"recentActionTimes", "recent_action_times"}};
            for (String[] n : names) if (c.containsKey(n[0])) sc.put(n[1], c.get(n[0]));
            return Caveats.evaluateCaveats(List.of(cv), sc).ok;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return false;
        }
    }

    // ======================================================================================================================
    // 4. Capability introspection
    // ======================================================================================================================

    private static final List<String> REV = Caveats.REVERSIBILITY_ORDER;
    private static final Object UNDECIDED = new Object();

    @SuppressWarnings("unchecked")
    private static List<Object> lst(Object o) { return (List<Object>) o; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    private static List<Object> sortedUnique(List<Object> in) {
        Set<String> s = new LinkedHashSet<>();
        for (Object o : in) s.add((String) o);
        List<String> l = new ArrayList<>(s);
        l.sort(Json::compareUtf8);
        return new ArrayList<Object>(l);
    }

    private static List<Object> intersectVerbs(List<Object> a, List<Object> b) {
        if (a.contains("*")) return sortedUnique(b);
        if (b.contains("*")) return sortedUnique(a);
        List<Object> r = new ArrayList<>();
        for (Object x : a) if (b.contains(x)) r.add(x);
        return sortedUnique(r);
    }

    /** Intersect two resource patterns: null = empty, {@link #UNDECIDED} = cannot decide symbolically (regex). */
    private static Object interRes(String a, String b) {
        if (a.equals(b)) return a;
        if (a.startsWith("re:") || b.startsWith("re:")) return UNDECIDED;
        if (a.equals("*")) return b;
        if (b.equals("*")) return a;
        boolean ap = a.endsWith("*"), bp = b.endsWith("*");
        if (ap && bp) {
            String pa = a.substring(0, a.length() - 1), pb = b.substring(0, b.length() - 1);
            return pb.startsWith(pa) ? b : pa.startsWith(pb) ? a : null;
        }
        if (ap) return b.startsWith(a.substring(0, a.length() - 1)) ? b : null;
        if (bp) return a.startsWith(b.substring(0, b.length() - 1)) ? a : null;
        return null;
    }

    /** Collapse a conjunction of resource patterns; null = unsatisfiable. */
    private static List<Object> collapseResources(List<Object> list) {
        String lit = null;
        Set<String> res = new LinkedHashSet<>();
        for (Object po : list) {
            String p = (String) po;
            if (p.startsWith("re:")) { res.add(p); continue; }
            if (lit == null) lit = p;
            else {
                Object r = interRes(lit, p);
                if (r == null || r == UNDECIDED) return null;
                lit = (String) r;
            }
        }
        List<String> sortedRes = new ArrayList<>(res);
        sortedRes.sort(Json::compareUtf8);
        List<Object> out = new ArrayList<>();
        if (lit != null && !lit.equals("*")) out.add(lit);
        out.addAll(sortedRes);
        if (out.isEmpty()) out.add("*");
        return out;
    }

    private static Map<String, Object> scope(List<Object> verbs, List<Object> resources, List<Object> where) {
        return Issue.obj("verbs", verbs, "resources", resources, "where", where);
    }

    private static Map<String, Object> universe() { return scope(new ArrayList<>(List.of("*")), new ArrayList<>(List.of("*")), new ArrayList<>()); }

    private static Map<String, Object> scopeOfPredicate(Object p) {
        if (!(p instanceof Map)) return null;
        Map<?, ?> pm = (Map<?, ?>) p;
        Object verb = pm.get("verb");
        List<Object> verbs;
        if (verb instanceof String) verbs = new ArrayList<>(List.of(verb));
        else if (verb instanceof List) {
            for (Object v : (List<?>) verb) if (!(v instanceof String)) return null;
            verbs = new ArrayList<>((List<?>) verb);
        } else return null;
        if (pm.containsKey("resource") && !(pm.get("resource") instanceof String)) return null;
        List<Object> where;
        if (!pm.containsKey("where")) where = new ArrayList<>();
        else if (pm.get("where") instanceof List) where = lst(pm.get("where"));
        else return null;
        List<Object> resources = new ArrayList<>();
        resources.add(pm.containsKey("resource") ? pm.get("resource") : "*");
        return scope(sortedUnique(verbs), resources, where);
    }

    private static List<Map<String, Object>> intersectScopes(List<Map<String, Object>> a, List<Map<String, Object>> b) {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Map<String, Object> x : a) {
            for (Map<String, Object> y : b) {
                List<Object> verbs = intersectVerbs(lst(x.get("verbs")), lst(y.get("verbs")));
                if (verbs.isEmpty()) continue;
                List<Object> both = new ArrayList<>(lst(x.get("resources")));
                both.addAll(lst(y.get("resources")));
                List<Object> resources = collapseResources(both);
                if (resources == null) continue;
                List<Object> where = new ArrayList<>(lst(x.get("where")));
                where.addAll(lst(y.get("where")));
                Map<String, Object> s = scope(verbs, resources, where);
                out.put(hash(s), s);
            }
        }
        List<String> keys = new ArrayList<>(out.keySet());
        keys.sort(String::compareTo);
        List<Map<String, Object>> r = new ArrayList<>();
        for (String k : keys) r.add(out.get(k));
        return r;
    }

    private static boolean scopeMatches(Map<String, Object> s, Object verb, Object resource, Object params) {
        List<Object> verbs = lst(s.get("verbs"));
        if (!verbs.contains("*") && !verbs.contains(verb)) return false;
        Map<String, Object> action = Issue.obj("verb", verb, "resource", resource);
        if (params != null) action.put("params", params);
        Map<String, Object> ctx = Issue.obj("action", action);
        for (Object r : lst(s.get("resources"))) if (!Predicates.predicateMatches(Issue.obj("verb", "*", "resource", r), ctx)) return false;
        if (params != null && !lst(s.get("where")).isEmpty()) return Predicates.predicateMatches(Issue.obj("verb", "*", "where", s.get("where")), ctx);
        return true;
    }

    /** Is this caveat one the verifier (stock evaluator + this module's superset) can satisfy at all? */
    private static boolean wellFormedCaveat(Map<?, ?> cv) {
        Object t = cv.get("type");
        if (!(t instanceof String)) return false;
        switch ((String) t) {
            case CAVEAT_EXPIRES:
            case CAVEAT_NOT_BEFORE:
                return fin(cv.get("at")) != null;
            case CAVEAT_RATE: {
                Double max = fin(cv.get("max")), per = fin(cv.get("per_secs"));
                return max != null && per != null && per > 0;
            }
            case CAVEAT_MAX_BLAST_RADIUS:
            case CAVEAT_DELEGATION_DEPTH:
                return fin(cv.get("max")) != null;
            case CAVEAT_REVERSIBILITY_MAX:
                return cv.get("class") instanceof String && REV.contains(cv.get("class"));
            case CAVEAT_PREDICATES:
                if (!(cv.get("allow") instanceof List)) return false;
                for (Object p : (List<?>) cv.get("allow")) if (scopeOfPredicate(p) == null) return false;
                return true;
            case CAVEAT_TOOL_SCHEMA:
                return nonEmpty(cv.get("tool"));
            case "budget_alloc": {
                Double lim = fin(cv.get("limit"));
                return lim != null && lim >= 0;
            }
            case CAVEAT_MAX_SPEND: {
                Double lim = fin(cv.get("usd"));
                return lim != null && lim >= 0;
            }
            default:
                return false;
        }
    }

    /** The mutable state of one {@link #describeEnvelope} fold. */
    private static final class Fold {
        List<Map<String, Object>> scopes;
        List<Object> tools;
        boolean seenEnvelope;
        final Set<String> bad = new LinkedHashSet<>();
        final List<Object> toolSchemas = new ArrayList<>();
        Double expiresAt, notBefore, maxBlast, depthRem, budgetAlloc, maxSpend;
        double[] maxRate;
        String revMax;
        final int chainLen;
        Fold(int chainLen) { this.chainLen = chainLen; }

        void fold(Object cvO, boolean inEnvelope) {
            if (!(cvO instanceof Map) || !(((Map<?, ?>) cvO).get("type") instanceof String)) { bad.add("<malformed>"); return; }
            Map<String, Object> cv = mp(cvO);
            String type = (String) cv.get("type");
            if (type.equals(CAVEAT_ENVELOPE)) {
                // only the root's FIRST envelope caveat is read; the policy VM evaluates any other as unknown => unsatisfied
                if (seenEnvelope || inEnvelope) bad.add(CAVEAT_ENVELOPE);
                seenEnvelope = true;
                return;
            }
            if (!wellFormedCaveat(cv)) { bad.add(type); return; }
            switch (type) {
                case CAVEAT_PREDICATES: {
                    List<Map<String, Object>> next = new ArrayList<>();
                    for (Object p : lst(cv.get("allow"))) next.add(scopeOfPredicate(p));
                    List<Map<String, Object>> cur = scopes != null ? scopes : new ArrayList<>(List.of(universe()));
                    scopes = intersectScopes(cur, next);
                    break;
                }
                case CAVEAT_TOOL_SCHEMA: {
                    toolSchemas.add(cv);
                    boolean consistent = Authorize.validateArgSchema(cv.get("schema")) == null
                        && hash(cv.get("schema")).equals(cv.get("schema_digest"))
                        && bindingOf(cv.get("tool"), IntentRevocation.jsText(cv.get("signature_digest"), cv.containsKey("signature_digest")), cv.get("schema"))
                            .equals(cv.get("binding_digest"));
                    if (!consistent) {
                        tools = new ArrayList<>();
                        bad.add(CAVEAT_TOOL_SCHEMA);
                    } else if (tools == null) {
                        tools = new ArrayList<>(List.of(cv.get("tool")));
                    } else {
                        List<Object> keep = new ArrayList<>();
                        for (Object t : tools) if (t.equals(cv.get("tool"))) keep.add(t);
                        tools = keep;
                    }
                    break;
                }
                case CAVEAT_EXPIRES: { double at = fin(cv.get("at")); expiresAt = expiresAt == null ? at : Math.min(expiresAt, at); break; }
                case CAVEAT_NOT_BEFORE: { double at = fin(cv.get("at")); notBefore = notBefore == null ? at : Math.max(notBefore, at); break; }
                case CAVEAT_RATE: {
                    double m = fin(cv.get("max")), p = fin(cv.get("per_secs"));
                    // the lower sustained rate (max / per_secs) binds; ties go to the smaller max
                    if (maxRate == null || m / p < maxRate[0] / maxRate[1] || (m / p == maxRate[0] / maxRate[1] && m < maxRate[0])) maxRate = new double[] {m, p};
                    break;
                }
                case CAVEAT_MAX_BLAST_RADIUS: { double m = fin(cv.get("max")); maxBlast = maxBlast == null ? m : Math.min(maxBlast, m); break; }
                case CAVEAT_REVERSIBILITY_MAX: {
                    int i = REV.indexOf(cv.get("class"));
                    int j = revMax == null ? REV.size() : REV.indexOf(revMax);
                    if (i < j) revMax = REV.get(i);
                    break;
                }
                case CAVEAT_DELEGATION_DEPTH: {
                    double rem = fin(cv.get("max")) - (chainLen - 1);
                    depthRem = depthRem == null ? rem : Math.min(depthRem, rem);
                    break;
                }
                case "budget_alloc": { double lim = fin(cv.get("limit")); budgetAlloc = budgetAlloc == null ? lim : Math.min(budgetAlloc, lim); break; }
                case CAVEAT_MAX_SPEND: { double lim = fin(cv.get("usd")); maxSpend = maxSpend == null ? lim : Math.min(maxSpend, lim); break; }
                default: break;
            }
        }
    }

    private static Map<String, Object> emptyEnvelope() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("hasEnvelope", false);
        m.put("scopes", new ArrayList<Object>());
        m.put("verbs", new ArrayList<Object>());
        m.put("resources", new ArrayList<Object>());
        m.put("opaqueResourceConstraints", new ArrayList<Object>());
        m.put("tools", new ArrayList<Object>());
        m.put("toolSchemas", new ArrayList<Object>());
        m.put("unsatisfiable", new ArrayList<Object>());
        m.put("caveats", new ArrayList<Object>());
        m.put("remainingBudgetHints", new LinkedHashMap<String, Object>());
        return m;
    }

    /**
     * What an attenuated chain permits NOW: the intersection across every hop of the root {@code envelope.predicates}, each appended
     * {@code predicates} / {@code tool_schema} caveat and the built-in caveats, exactly the set the verifier would accept. Returns the
     * {@code AuthorityEnvelope} as a JSON map: {@code {ok, reason?, hasEnvelope, scopes, verbs, resources, opaqueResourceConstraints,
     * tools, toolSchemas, unsatisfiable, caveats, remainingBudgetHints}}. {@code scopes} / {@code verbs} / {@code resources} /
     * {@code tools} are null when unrestricted. A caveat the verifier cannot satisfy makes the envelope unsatisfiable (nothing is
     * permitted). {@code policy} may carry {@code allowedSuites}, {@code pqPins}, {@code trustedRoot}. A chain that does not verify
     * gives {@code ok: false} with the verifier's reason. Deterministic ({@code now} supplied) and total.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> describeEnvelope(Object chain, Object now, String expectedRootIssuer, Map<String, Object> policy) {
        Map<String, Object> empty = emptyEnvelope();
        try {
            List<Object> ch = chain instanceof List ? (List<Object>) chain : new ArrayList<>();
            List<String> allowed = policy != null && policy.get("allowedSuites") instanceof List ? (List<String>) (List<?>) policy.get("allowedSuites") : null;
            Map<String, Object> pins = policy != null && policy.get("pqPins") instanceof Map ? mp(policy.get("pqPins")) : null;
            Map<String, Object> trusted = policy != null && policy.get("trustedRoot") instanceof Map ? mp(policy.get("trustedRoot")) : null;
            String why = Pca.verifyChain(ch, expectedRootIssuer, expectedRootIssuer != null, allowed, pins, trusted);
            if (!why.isEmpty()) { empty.put("reason", why); return empty; }

            Map<String, Object> root = mp(ch.get(0)), leaf = mp(ch.get(ch.size() - 1));
            Map<String, Object> env0 = Authorize.readEnvelope(root);
            Map<String, Object> env = emptyEnvelope();
            env.put("ok", true);
            env.put("hasEnvelope", env0 != null);
            env.put("caveats", leaf.get("caveats"));
            Fold f = new Fold(ch.size());

            if (env0 != null) {
                List<Map<String, Object>> base = new ArrayList<>();
                for (Object p : lst(env0.get("predicates"))) {
                    Map<String, Object> s = scopeOfPredicate(p);
                    if (s == null) f.bad.add("envelope.predicates"); else base.add(s);
                }
                f.scopes = intersectScopes(base, new ArrayList<>(List.of(universe())));
            }
            if (env0 != null) for (Object cv : lst(env0.get("caveats"))) f.fold(cv, true);
            for (Object cv : lst(leaf.get("caveats"))) f.fold(cv, false);

            Set<String> opaque = new LinkedHashSet<>();
            if (f.scopes != null) {
                Set<String> vs = new LinkedHashSet<>(), rs = new LinkedHashSet<>();
                for (Map<String, Object> s : f.scopes) {
                    for (Object v : lst(s.get("verbs"))) vs.add((String) v);
                    for (Object r : lst(s.get("resources"))) { rs.add((String) r); if (((String) r).startsWith("re:")) opaque.add((String) r); }
                }
                env.put("scopes", new ArrayList<Object>(f.scopes));
                env.put("verbs", sortedUnique(new ArrayList<Object>(vs)));
                env.put("resources", sortedUnique(new ArrayList<Object>(rs)));
            } else {
                env.put("scopes", null);
                env.put("verbs", null);
                env.put("resources", null);
            }
            env.put("opaqueResourceConstraints", sortedUnique(new ArrayList<Object>(opaque)));
            env.put("tools", f.tools == null ? null : sortedUnique(f.tools));
            env.put("toolSchemas", f.toolSchemas);
            List<Object> unsat = sortedUnique(new ArrayList<Object>(f.bad));
            env.put("unsatisfiable", unsat);
            if (!unsat.isEmpty()) {
                env.put("scopes", new ArrayList<Object>());
                env.put("verbs", new ArrayList<Object>());
                env.put("resources", new ArrayList<Object>());
                env.put("tools", new ArrayList<Object>());
                StringBuilder sb = new StringBuilder("unsatisfiable caveat(s): ");
                for (int i = 0; i < unsat.size(); i++) sb.append(i > 0 ? ", " : "").append(unsat.get(i));
                env.put("reason", sb.toString());
            }
            Map<String, Object> h = mp(env.get("remainingBudgetHints"));
            if (f.expiresAt != null) h.put("expiresAt", f.expiresAt);
            Double nowF = fin(now);
            if (f.expiresAt != null && nowF != null) h.put("expiresIn", f.expiresAt - nowF);
            if (f.maxRate != null) h.put("maxRate", Issue.obj("max", f.maxRate[0], "per_secs", f.maxRate[1]));
            if (f.maxBlast != null) h.put("maxBlastRadius", f.maxBlast);
            if (f.revMax != null) h.put("reversibilityMax", f.revMax);
            if (f.depthRem != null) h.put("delegationDepthRemaining", f.depthRem);
            if (f.notBefore != null) h.put("notBefore", f.notBefore);
            if (f.budgetAlloc != null) h.put("budgetAlloc", f.budgetAlloc);
            if (f.maxSpend != null) h.put("maxSpendUsd", f.maxSpend);
            return env;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            Map<String, Object> m = emptyEnvelope();
            m.put("reason", "introspection error (fail closed)");
            return m;
        }
    }

    /**
     * Pre-flight an agent can run before attempting. False is definitive (the verifier will refuse); true means the symbolic envelope
     * allows it. When {@code params} is given the {@code where} conditions are evaluated too (fail closed); {@code now} and
     * {@code params} are null when not given. Total.
     */
    public static boolean envelopePermits(Object envO, Object verb, Object resource, Object now, Object params) {
        try {
            if (!(envO instanceof Map)) return false;
            Map<String, Object> env = mp(envO);
            if (!IntentRevocation.truthy(env.get("ok")) || !lst(env.get("unsatisfiable")).isEmpty()) return false;
            if (!env.containsKey("scopes")) return false;
            if (env.get("scopes") != null) {
                boolean any = false;
                for (Object s : lst(env.get("scopes"))) if (scopeMatches(mp(s), verb, resource, params)) { any = true; break; }
                if (!any) return false;
            }
            Map<String, Object> h = mp(env.get("remainingBudgetHints"));
            Double depth = h.containsKey("delegationDepthRemaining") ? IntentJs.num(h.get("delegationDepthRemaining")) : null;
            if (depth != null && !(Double.isFinite(depth) && depth >= 0)) return false;
            Double maxSpend = h.containsKey("maxSpendUsd") ? IntentJs.num(h.get("maxSpendUsd")) : null;
            if (maxSpend != null && params != null) {
                Double spend = actionSpendUsd(Issue.obj("action", Issue.obj("params", params)));
                if (spend == null || !(Double.isFinite(spend) && spend <= maxSpend)) return false;
            }
            if (now != null) {
                Double n = fin(now);
                if (n == null) return false;
                Double exp = h.containsKey("expiresAt") ? IntentJs.num(h.get("expiresAt")) : null;
                if (exp != null && !(Double.isFinite(exp) && n < exp)) return false;
                Double nb = h.containsKey("notBefore") ? IntentJs.num(h.get("notBefore")) : null;
                if (nb != null && !(Double.isFinite(nb) && n >= nb)) return false;
            }
            return true;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return false;
        }
    }

    private static Map<String, Object> firewall(boolean ok, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /** Pre-flight for a tool call: the tool must be in {@code env.tools} and satisfy EVERY {@code tool_schema} caveat. Returns {@code {ok, reason?}}. */
    public static Map<String, Object> envelopePermitsToolCall(Object envO, Object call) {
        try {
            Map<String, Object> env = mp(envO);
            if (!IntentRevocation.truthy(env.get("ok")) || !lst(env.get("unsatisfiable")).isEmpty()) {
                return firewall(false, env.get("reason") != null ? String.valueOf(env.get("reason")) : "envelope not usable");
            }
            if (env.get("tools") != null) {
                if (call == null) throw new IllegalStateException("call is null"); // the reference reads call.tool
                Map<?, ?> c = call instanceof Map ? (Map<?, ?>) call : null; // any other value has no tool member (undefined)
                boolean has = c != null && c.containsKey("tool");
                if (!(has && lst(env.get("tools")).contains(c.get("tool")))) {
                    return firewall(false, "tool " + Authorize.show(IntentRevocation.jsText(has ? c.get("tool") : null, has)) + " not authorized");
                }
            }
            for (Object tc : lst(env.get("toolSchemas"))) {
                Authorize.ToolSchemaResult r = Authorize.evaluateToolSchema(tc, call);
                if (!r.ok) return firewall(false, r.reason);
            }
            return firewall(true, null);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return firewall(false, "evaluation error (fail closed)");
        }
    }

    // ======================================================================================================================
    // 5. Authority lease
    // ======================================================================================================================

    /**
     * Issue a lease {@code {cap_id, holder, issued_at, renewed_at, ttl_ms, renewals, last_seq, expires_at, hard_expires_at?,
     * max_renewals?}} from {@code {cap_id, holder, now, ttl_ms, hard_expires_at?, max_renewals?}}. Throws unless the ids are non-empty,
     * {@code now} finite, 0 &lt; ttl_ms &lt;= {@link #MAX_LEASE_TTL_MS}, {@code hard_expires_at} (if any) finite and after {@code now},
     * and {@code max_renewals} (if any) a non-negative integer.
     */
    public static Map<String, Object> grantLease(Object argsO) {
        if (!(argsO instanceof Map)) throw new IllegalArgumentException("grantLease: cap_id and holder required");
        Map<?, ?> a = (Map<?, ?>) argsO;
        if (!nonEmpty(a.get("cap_id")) || !nonEmpty(a.get("holder"))) throw new IllegalArgumentException("grantLease: cap_id and holder required");
        Double now = fin(a.get("now")), ttl = fin(a.get("ttl_ms"));
        if (now == null || ttl == null || ttl <= 0 || ttl > MAX_LEASE_TTL_MS) throw new IllegalArgumentException("grantLease: invalid now/ttl_ms");
        Double hard = null;
        if (a.containsKey("hard_expires_at")) {
            hard = fin(a.get("hard_expires_at"));
            if (hard == null || hard <= now) throw new IllegalArgumentException("grantLease: hard_expires_at must be finite and in the future");
        }
        if (a.containsKey("max_renewals") && !isNonNegInteger(a.get("max_renewals"))) throw new IllegalArgumentException("grantLease: invalid max_renewals");
        double exp = hard == null ? now + ttl : Math.min(now + ttl, hard);
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("cap_id", a.get("cap_id"));
        l.put("holder", a.get("holder"));
        l.put("issued_at", a.get("now"));
        l.put("renewed_at", a.get("now"));
        l.put("ttl_ms", a.get("ttl_ms"));
        l.put("renewals", 0L);
        l.put("last_seq", 0L);
        l.put("expires_at", exp);
        if (hard != null) l.put("hard_expires_at", a.get("hard_expires_at"));
        if (a.containsKey("max_renewals")) l.put("max_renewals", a.get("max_renewals"));
        return l;
    }

    /** Structural + invariant check of a lease record: an error or null. */
    private static String leaseError(Object lo) {
        if (!(lo instanceof Map)) return "malformed lease";
        Map<?, ?> l = (Map<?, ?>) lo;
        if (!nonEmpty(l.get("cap_id")) || !nonEmpty(l.get("holder"))) return "malformed lease";
        Double issued = fin(l.get("issued_at")), renewed = fin(l.get("renewed_at")), ttl = fin(l.get("ttl_ms")), exp = fin(l.get("expires_at"));
        if (issued == null || renewed == null || ttl == null || exp == null) return "malformed lease";
        if (ttl <= 0 || ttl > MAX_LEASE_TTL_MS) return "malformed lease";
        if (!isNonNegInteger(l.get("renewals")) || !isNonNegInteger(l.get("last_seq"))) return "malformed lease";
        if (l.containsKey("max_renewals") && !isNonNegInteger(l.get("max_renewals"))) return "malformed lease";
        if (l.containsKey("hard_expires_at")) {
            Double hard = fin(l.get("hard_expires_at"));
            if (hard == null) return "malformed lease";
            if (exp > hard) return "lease exceeds hard expiry";
        }
        // a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
        if (exp > renewed + ttl) return "malformed lease";
        return null;
    }

    private static Map<String, Object> dead(String reason) {
        return Issue.obj("live", false, "expiresIn", 0L, "reason", reason);
    }

    /**
     * Live iff the record is well-formed, the clock has not rolled back more than the skew window past the last renewal and
     * {@code now < expires_at}. Returns {@code {live, expiresIn, reason?}}; every dead state has {@code expiresIn} 0. Total.
     */
    public static Map<String, Object> leaseState(Object lease, Object now) {
        Double n = fin(now);
        if (n == null) return dead("invalid clock");
        String e = leaseError(lease);
        if (e != null) return dead(e);
        Map<?, ?> l = (Map<?, ?>) lease;
        if (n < fin(l.get("renewed_at")) - HEARTBEAT_SKEW_MS) return dead("clock before last renewal");
        double expiresIn = fin(l.get("expires_at")) - n;
        if (expiresIn <= 0) return dead("lease lapsed");
        return Issue.obj("live", true, "expiresIn", expiresIn);
    }

    private static final List<String> HB_KEYS = List.of("cap_id", "seq", "at", "holder", "lease_issued_at", "sig");

    private static Map<String, Object> renewFail(String reason) { return Issue.obj("ok", false, "reason", reason); }

    /**
     * The reference's pure {@code renewLease(lease, heartbeat, now)} (the grants registry keeps {@link Lease}'s own {@code renewLease}):
     * renew on a valid, fresh, in-order, holder-signed heartbeat for THIS lease grant. A lapsed, malformed or clock-anomalous lease is
     * dead for good. Never extends past {@code hard_expires_at}, never shortens, consumes the renewal budget. Returns
     * {@code {ok: true, lease}} or {@code {ok: false, reason}}. Total.
     */
    public static Map<String, Object> renewCapabilityLease(Object leaseO, Object hbO, Object nowO) {
        try {
            Map<String, Object> st = leaseState(leaseO, nowO);
            if (!Boolean.TRUE.equals(st.get("live"))) {
                return renewFail("lease lapsed".equals(st.get("reason")) ? "lease lapsed" : "lease not live: " + st.get("reason"));
            }
            Map<String, Object> lease = mp(leaseO);
            double now = fin(nowO);
            if (!(hbO instanceof Map)) return renewFail("malformed heartbeat");
            Map<String, Object> hb = mp(hbO);
            for (Object k : hb.keySet()) if (!HB_KEYS.contains(k)) return renewFail("malformed heartbeat");
            if (!(hb.get("sig") instanceof String)) return renewFail("malformed heartbeat");
            if (!Authorize.jsEq(hb.get("cap_id"), lease.get("cap_id")) || !Authorize.jsEq(hb.get("holder"), lease.get("holder"))
                    || !Authorize.jsEq(hb.get("lease_issued_at"), lease.get("issued_at"))) return renewFail("heartbeat not for this lease");
            Object seq = hb.get("seq");
            if (!IntentJs.isSafeInteger(seq) || IntentJs.num(seq) <= fin(lease.get("last_seq"))) return renewFail("stale or replayed heartbeat");
            Double at = fin(hb.get("at"));
            if (at == null || Math.abs(at - now) > HEARTBEAT_SKEW_MS) return renewFail("heartbeat outside skew window");
            Map<String, Object> body = new LinkedHashMap<>(hb);
            body.remove("sig");
            if (!Pca.verifyB64u((String) lease.get("holder"), msgOf("atlas-pca/lease-hb/v2", body), (String) hb.get("sig"))) return renewFail("bad heartbeat signature");
            if (lease.containsKey("max_renewals") && fin(lease.get("renewals")) >= fin(lease.get("max_renewals"))) return renewFail("renewal budget exhausted");
            double exp = now + fin(lease.get("ttl_ms"));
            if (lease.containsKey("hard_expires_at")) exp = Math.min(exp, fin(lease.get("hard_expires_at")));
            if (Double.isNaN(exp) || Double.isInfinite(exp)) return renewFail("malformed lease");
            Map<String, Object> next = new LinkedHashMap<>(lease);
            next.put("renewals", fin(lease.get("renewals")) + 1);
            next.put("last_seq", seq);
            next.put("renewed_at", Math.max(now, fin(lease.get("renewed_at"))));
            next.put("expires_at", Math.max(exp, fin(lease.get("expires_at"))));
            return Issue.obj("ok", true, "lease", next);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return renewFail("malformed heartbeat");
        }
    }
}
