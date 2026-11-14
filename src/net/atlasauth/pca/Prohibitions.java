package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The prohibition engine (the reference's {@code prohibitions.ts}): a signed constitution of invariants (never, never_unless, cap, rate, never_after,
 * require_prior, require_approval_over) checked against every action, over a canonical, hash-chained monitor state, with per-action safety evidence.
 * The veto trigger ({@code whenMatches}) is {@link ForbidWins#whenMatches}. Everything is pure and total: anything malformed, unknown or unresolvable
 * fails closed and nothing here throws. Values are JSON trees ({@link Json.Num} numbers); the JavaScript semantics the reference relies on are kept
 * (a missing property reads as undefined, {@code String(null)} is {@code "null"}, lengths count UTF-16 units).
 */
public final class Prohibitions {
    private Prohibitions() {}

    public static final int CONSTITUTION_VERSION = 1;
    public static final String CONSTITUTION_SIG_DOMAIN = "atlas-pca/constitution/v1\u0000";
    public static final int EVIDENCE_VERSION = 1;
    public static final String STATE_DIGEST_DOMAIN = "atlas-pca/monitor-state/v1";
    public static final String STATE_CHAIN_DOMAIN = "atlas-pca/monitor-state-link/v1";
    public static final int MAX_LEDGER = 10_000;
    public static final int MAX_INVARIANTS = 256;
    public static final int MAX_DEADLINE = 1_000_000;
    static final int MAX_STATE_ENTRIES = 100_000;
    static final int MAX_STATE_KEYS = 1024;
    static final int MAX_ID_LEN = 128;
    static final Set<String> FORBIDDEN_IDS = new HashSet<>(Arrays.asList("__proto__", "constructor", "prototype"));
    public static final String UNHASHABLE = "<unhashable>";
    /** An absent property (JavaScript {@code undefined}), distinct from a JSON null. */
    static final Object UNDEF = new Object();
    /** The default of an omitted optional argument (JavaScript {@code undefined}): an explicit null is a value, as in the reference. */
    static final Object ABSENT = new Object();

    // ---- JavaScript-flavoured helpers

    static boolean isObj(Object o) { return o instanceof Map; }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) { return (List<Object>) o; }

    static boolean fin(Object o) { return Caveats.fin(o) != null; }

    static double dv(Object o) { return Caveats.fin(o); }

    /** {@code Number.isInteger}. */
    static boolean isInteger(Object o) {
        Double d = Caveats.fin(o);
        return d != null && d == Math.floor(d);
    }

    static boolean negZero(Object o) {
        Double d = Caveats.fin(o);
        return d != null && d == 0 && 1 / d < 0;
    }

    static Object jn(double d) { return new Json.Num(AttestCommon.jsNumString(d)); }

    /** {@code o.k}: undefined on a non-object. */
    static Object prop(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k) ? ((Map<?, ?>) o).get(k) : UNDEF; }

    static Object get(Map<String, Object> m, String k) { return m.containsKey(k) ? m.get(k) : UNDEF; }

    static boolean present(Object v) { return v != UNDEF; }

    /** JavaScript {@code String(x)}; {@code UNDEF} reads {@code "undefined"}. */
    static String text(Object v) { return v == UNDEF ? "undefined" : IntentRevocation.jsText(v, true); }

    static boolean truthy(Object v) { return v != UNDEF && IntentRevocation.truthy(v); }

    static boolean strEq(Object a, String b) { return b.equals(a); }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static byte[] domainMessage(String domain, String id) {
        byte[] d = domain.getBytes(StandardCharsets.UTF_8);
        byte[] h = AttestCommon.sha256Sum(id.getBytes(StandardCharsets.UTF_8));
        return Pca.concat(d, h);
    }

    static String safe(Supplier<String> f) {
        try {
            return f.get();
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return UNHASHABLE;
        }
    }

    // ---- constitution

    /** Genesis monitor state at time {@code now}: empty ledger, no latches, seq 0, no parent. */
    public static Map<String, Object> emptyState(Object now) {
        return map("now", now, "seq", jn(0), "parent", null, "ledger", new LinkedHashMap<String, Object>(), "latched", new LinkedHashMap<String, Object>());
    }

    static Map<String, Object> body(Map<String, Object> c) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : c.entrySet()) if (!e.getKey().equals("id") && !e.getKey().equals("sig")) b.put(e.getKey(), e.getValue());
        return b;
    }

    public static String constitutionId(Map<String, Object> c) { return Pca.hashCanonical(body(c)); }

    private static boolean actionPath(Object v) { return v instanceof String && ((String) v).startsWith("action."); }

    private static String validateConditions(Object cs, String label) {
        if (!(cs instanceof List) || ((List<?>) cs).isEmpty()) return label + " must be a non-empty array";
        for (Object c : (List<?>) cs) {
            String e = ForbidWins.validateCondition(c, 0);
            if (e != null) return e;
        }
        return null;
    }

    private static List<String> one(String s) { return new ArrayList<>(List.of(s)); }

    /** Structural problems with an invariant (empty = well formed). */
    public static List<String> validateInvariant(Object invO) {
        if (!isObj(invO)) return one("invariant not an object");
        Map<String, Object> inv = obj(invO);
        Object rawId = inv.get("id");
        if (!(rawId instanceof String) || ((String) rawId).isEmpty()) return one("<no id>: missing id");
        String id = (String) rawId;
        if (id.length() > MAX_ID_LEN) return one(id + ": id too long");
        if (FORBIDDEN_IDS.contains(id)) return one(id + ": forbidden id");
        Object kind = get(inv, "kind");
        String e;
        if ("never".equals(kind)) {
            e = ForbidWins.validateWhen(inv.get("when"), "when");
            return e != null ? one(id + ": " + e) : new ArrayList<>();
        }
        if ("never_unless".equals(kind)) {
            e = ForbidWins.validateWhen(inv.get("when"), "when");
            if (e == null) e = validateConditions(inv.get("unless"), "unless");
            return e != null ? one(id + ": " + e) : new ArrayList<>();
        }
        if ("cap".equals(kind)) {
            e = ForbidWins.validateWhen(inv.get("when"), "when");
            if (e != null) return one(id + ": " + e);
            if (!actionPath(inv.get("amount"))) return one(id + ": amount must be an action.* path");
            if (!fin(inv.get("max")) || dv(inv.get("max")) < 0) return one(id + ": max must be a finite number >= 0");
            if (inv.containsKey("window_secs") && (!fin(inv.get("window_secs")) || dv(inv.get("window_secs")) <= 0)) return one(id + ": bad window_secs");
            return new ArrayList<>();
        }
        if ("rate".equals(kind)) {
            e = ForbidWins.validateWhen(inv.get("when"), "when");
            if (e != null) return one(id + ": " + e);
            Object m = inv.get("max");
            if (!isInteger(m) || dv(m) < 0 || negZero(m) || dv(m) > MAX_LEDGER) return one(id + ": max must be an integer in [0,10000]");
            if (!fin(inv.get("window_secs")) || dv(inv.get("window_secs")) <= 0) return one(id + ": window_secs must be > 0");
            return new ArrayList<>();
        }
        if ("never_after".equals(kind)) {
            e = ForbidWins.validateWhen(inv.get("after"), "after");
            if (e == null) e = ForbidWins.validateWhen(inv.get("forbid"), "forbid");
            return e != null ? one(id + ": " + e) : new ArrayList<>();
        }
        if ("require_prior".equals(kind)) {
            e = ForbidWins.validateWhen(inv.get("when"), "when");
            if (e == null) e = ForbidWins.validateWhen(inv.get("prior"), "prior");
            return e != null ? one(id + ": " + e) : new ArrayList<>();
        }
        if ("require_approval_over".equals(kind)) {
            e = ForbidWins.validateWhen(inv.get("when"), "when");
            if (e != null) return one(id + ": " + e);
            if (!actionPath(inv.get("amount"))) return one(id + ": amount must be an action.* path");
            if (!fin(inv.get("threshold")) || dv(inv.get("threshold")) < 0) return one(id + ": threshold must be a finite number >= 0");
            e = validateConditions(inv.get("approved"), "approved");
            return e != null ? one(id + ": " + e) : new ArrayList<>();
        }
        return one(id + ": unknown invariant kind " + text(kind));
    }

    /** Structural problems with a constitution (empty = well formed). */
    public static List<String> validateConstitution(Object cO) {
        if (!isObj(cO)) return one("constitution not an object");
        Map<String, Object> c = obj(cO);
        List<String> out = new ArrayList<>();
        Object version = c.get("version");
        if (!(fin(version) && dv(version) == CONSTITUTION_VERSION)) out.add("unsupported version " + text(get(c, "version")));
        if (!(c.get("principal") instanceof String) || ((String) c.get("principal")).isEmpty()) out.add("principal missing");
        Object invs = c.get("invariants");
        if (!(invs instanceof List)) {
            out.add("invariants not an array");
            return out;
        }
        List<Object> l = arr(invs);
        if (l.size() > MAX_INVARIANTS) out.add("too many invariants");
        Set<String> seen = new HashSet<>();
        for (Object inv : l) {
            out.addAll(validateInvariant(inv));
            Object id = isObj(inv) ? obj(inv).get("id") : null;
            if (id instanceof String) {
                if (!seen.add((String) id)) out.add(id + ": duplicate id");
            }
        }
        return out;
    }

    /** Well formed, id matches content, signature by {@code expectedPrincipal} (or the embedded one). Null when it verifies, else the reason. Never throws. */
    public static String verifyConstitution(Object sc, String expectedPrincipal) {
        try {
            List<String> problems = validateConstitution(sc);
            if (!problems.isEmpty()) return problems.get(0);
            Map<String, Object> c = obj(sc);
            if (expectedPrincipal != null && !expectedPrincipal.equals(c.get("principal"))) return "principal mismatch";
            if (!(c.get("id") instanceof String) || !c.get("id").equals(constitutionId(c))) return "id does not match content";
            if (!(c.get("sig") instanceof String) || !IntentJs.verifyEd(c.get("principal"), domainMessage(CONSTITUTION_SIG_DOMAIN, (String) c.get("id")), c.get("sig"))) return "bad signature";
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return "verification error (fail closed)";
        }
    }

    // ---- canonical monitor state

    /** The structural problem of a monitor state (null = well formed). Total. */
    public static String stateProblem(Object stateO) {
        try {
            if (!isObj(stateO)) return "malformed monitor state";
            Map<String, Object> state = obj(stateO);
            if (!fin(state.get("now")) || !isObj(state.get("ledger")) || !isObj(state.get("latched"))) return "malformed monitor state";
            Object seq = state.get("seq");
            if (!isInteger(seq) || dv(seq) < 0 || negZero(seq)) return "malformed monitor state: seq";
            Object parent = get(state, "parent");
            if (parent != null && !(parent instanceof String)) return "malformed monitor state: parent";
            if (dv(seq) == 0 && parent != null) return "malformed monitor state: genesis has a parent";
            if (dv(seq) > 0 && parent == null) return "malformed monitor state: missing chain link";
            double now = dv(state.get("now"));
            Map<String, Object> ledger = obj(state.get("ledger")), latched = obj(state.get("latched"));
            if (ledger.size() > MAX_STATE_KEYS || latched.size() > MAX_STATE_KEYS) return "malformed monitor state: too many keys";
            long total = 0;
            for (Map.Entry<String, Object> en : ledger.entrySet()) {
                String k = en.getKey();
                if (FORBIDDEN_IDS.contains(k) || k.length() > MAX_ID_LEN) return "malformed monitor state: bad ledger key";
                if (!(en.getValue() instanceof List) || arr(en.getValue()).size() > MAX_LEDGER) return "malformed monitor state: bad ledger";
                total += arr(en.getValue()).size();
                for (Object e : arr(en.getValue())) {
                    if (!isObj(e) || !fin(obj(e).get("t")) || !fin(obj(e).get("amount")) || dv(obj(e).get("amount")) < 0) return "malformed monitor state: bad ledger entry";
                    // an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
                    if (dv(obj(e).get("t")) > now) return "malformed monitor state: ledger entry after now (clock regression)";
                }
            }
            if (total > MAX_STATE_ENTRIES) return "malformed monitor state: too many entries";
            for (Map.Entry<String, Object> en : latched.entrySet()) {
                String k = en.getKey();
                if (FORBIDDEN_IDS.contains(k) || k.length() > MAX_ID_LEN) return "malformed monitor state: bad latch key";
                if (!fin(en.getValue()) || dv(en.getValue()) > now) return "malformed monitor state: bad latch";
            }
            if (state.containsKey("deadlines")) {
                Object dl = state.get("deadlines");
                if (!isObj(dl)) return "malformed monitor state: deadlines";
                if (obj(dl).size() > MAX_STATE_KEYS) return "malformed monitor state: too many deadline keys";
                for (Map.Entry<String, Object> en : obj(dl).entrySet()) {
                    String k = en.getKey();
                    if (FORBIDDEN_IDS.contains(k) || k.length() > MAX_ID_LEN) return "malformed monitor state: bad deadline key";
                    Object d = en.getValue();
                    if (!isInteger(d) || dv(d) < 1 || dv(d) > MAX_DEADLINE) return "malformed monitor state: bad deadline";
                }
            }
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return "malformed monitor state";
        }
    }

    /** {@code a.t - b.t || a.amount - b.amount} (the reference): -0 and 0 tie, so no Double.compare. */
    private static int cmpEntry(Map<String, Object> a, Map<String, Object> b) {
        double ta = dv(a.get("t")), tb = dv(b.get("t"));
        if (ta < tb) return -1;
        if (ta > tb) return 1;
        double x = dv(a.get("amount")), y = dv(b.get("amount"));
        return x < y ? -1 : x > y ? 1 : 0;
    }

    /** Canonical form of a state: unknown fields dropped, ledger entries reduced to {t, amount} and sorted, empty ledger arrays omitted. Throws on a malformed state. */
    public static Map<String, Object> canonicalState(Object stateO) {
        String p = stateProblem(stateO);
        if (p != null) throw new IllegalArgumentException(p);
        Map<String, Object> state = obj(stateO);
        Map<String, Object> ledger = new LinkedHashMap<>();
        for (Map.Entry<String, Object> en : obj(state.get("ledger")).entrySet()) {
            List<Map<String, Object>> l = new ArrayList<>();
            for (Object e : arr(en.getValue())) l.add(map("t", obj(e).get("t"), "amount", obj(e).get("amount")));
            l.sort(Prohibitions::cmpEntry);
            if (!l.isEmpty()) ledger.put(en.getKey(), new ArrayList<Object>(l));
        }
        Map<String, Object> base = map("d", STATE_DIGEST_DOMAIN, "now", state.get("now"), "seq", state.get("seq"), "parent", state.get("parent"),
            "ledger", ledger, "latched", new LinkedHashMap<>(obj(state.get("latched"))));
        if (state.containsKey("deadlines")) {
            Map<String, Object> dl = new LinkedHashMap<>(obj(state.get("deadlines")));
            if (!dl.isEmpty()) base.put("deadlines", dl);
        }
        return base;
    }

    public static String stateDigest(Object state) { return Pca.hashCanonical(canonicalState(state)); }

    /** The same state at a later {@code now}; refuses regression. {@code {ok, state}} or {@code {ok: false, reason}}. */
    public static Map<String, Object> tickState(Object state, Object now) {
        if (stateProblem(state) != null) return map("ok", false, "reason", "malformed monitor state");
        if (!fin(now) || dv(now) < dv(obj(state).get("now"))) return map("ok", false, "reason", "clock regression");
        Map<String, Object> next = new LinkedHashMap<>(obj(state));
        next.put("now", now);
        return map("ok", true, "state", next);
    }

    // ---- the monitor

    private static boolean allHold(Object cs, Map<String, Object> ctx) {
        for (Object c : arr(cs)) if (!Predicates.evaluateCondition(c, ctx)) return false;
        return true;
    }

    private static List<Map<String, Object>> windowEntries(Map<String, Object> state, String id, Object windowSecs) {
        Object l = obj(state.get("ledger")).get(id);
        List<Map<String, Object>> out = new ArrayList<>();
        if (!(l instanceof List)) return out;
        double now = dv(state.get("now"));
        double lo = windowSecs == null ? Double.NEGATIVE_INFINITY : now - dv(windowSecs) * 1000;
        for (Object e : arr(l)) {
            double t = dv(obj(e).get("t"));
            if (t > lo && t <= now) out.add(obj(e));
        }
        out.sort(Prohibitions::cmpEntry);
        return out;
    }

    /** {@code inv.description ?? dflt}: the raw value (a number, array or object description stays one in the row), as in the reference. */
    private static Object reasonOf(Map<String, Object> inv, String dflt) {
        Object d = inv.get("description");
        return d == null ? dflt : d;
    }

    private static Map<String, Object> okRes() { return map("ok", true); }

    private static Map<String, Object> bad(Object reason) { return map("ok", false, "reason", reason); }

    private static Map<String, Object> evalOne(Map<String, Object> inv, Map<String, Object> ctx, Map<String, Object> state) {
        String kind = (String) inv.get("kind");
        Map<String, Object> latched = obj(state.get("latched"));
        switch (kind) {
            case "never":
                return ForbidWins.whenMatches(inv.get("when"), ctx) ? bad(reasonOf(inv, "forbidden action")) : okRes();
            case "never_unless":
                if (!ForbidWins.whenMatches(inv.get("when"), ctx)) return okRes();
                return allHold(inv.get("unless"), ctx) ? okRes() : bad(reasonOf(inv, "forbidden without required condition"));
            case "cap": {
                if (!ForbidWins.whenMatches(inv.get("when"), ctx)) return okRes();
                Predicates.Resolved a = Predicates.resolvePath(ctx, inv.get("amount"));
                if (!a.found || !fin(a.value) || dv(a.value) < 0) return bad("amount unresolvable (fail closed)");
                double spent = 0;
                for (Map<String, Object> e : windowEntries(state, (String) inv.get("id"), inv.get("window_secs"))) spent += dv(e.get("amount"));
                double total = spent + dv(a.value);
                if (total <= dv(inv.get("max"))) return okRes();
                return bad("cap exceeded: " + AttestCommon.jsNumString(spent) + " + " + AttestCommon.jsNumString(dv(a.value)) + " > " + AttestCommon.jsNumString(dv(inv.get("max"))));
            }
            case "rate": {
                if (!ForbidWins.whenMatches(inv.get("when"), ctx)) return okRes();
                int n = windowEntries(state, (String) inv.get("id"), inv.get("window_secs")).size();
                if (n + 1 <= dv(inv.get("max"))) return okRes();
                return bad("rate exceeded: " + (n + 1) + " > " + AttestCommon.jsNumString(dv(inv.get("max"))) + " per " + AttestCommon.jsNumString(dv(inv.get("window_secs"))) + "s");
            }
            case "never_after":
                if (!latched.containsKey(inv.get("id")) || !ForbidWins.whenMatches(inv.get("forbid"), ctx)) return okRes();
                return bad(reasonOf(inv, "forbidden after trigger"));
            case "require_prior":
                if (!ForbidWins.whenMatches(inv.get("when"), ctx)) return okRes();
                return latched.containsKey(inv.get("id")) ? okRes() : bad(reasonOf(inv, "required prior action not admitted"));
            case "require_approval_over": {
                if (!ForbidWins.whenMatches(inv.get("when"), ctx)) return okRes();
                Predicates.Resolved a = Predicates.resolvePath(ctx, inv.get("amount"));
                boolean over = !a.found || !fin(a.value) || dv(a.value) < 0 || dv(a.value) > dv(inv.get("threshold"));
                if (!over) return okRes();
                return allHold(inv.get("approved"), ctx) ? okRes() : bad(reasonOf(inv, "approval required over " + AttestCommon.jsNumString(dv(inv.get("threshold")))));
            }
            default:
                throw new IllegalStateException("unknown invariant kind"); // unreachable after validation; the caller turns it into a fail-closed row
        }
    }

    static boolean actionOk(Object action) {
        Object a = action instanceof Map ? obj(action).get("action") : null;
        return a instanceof Map && obj(a).get("verb") instanceof String && obj(a).get("resource") instanceof String;
    }

    static Map<String, Object> structural(String id, String reason) {
        Map<String, Object> row = map("id", id, "kind", "structural", "result", "violated", "reason", reason);
        return map("ok", false, "violated", new ArrayList<Object>(List.of(id)), "reasons", new ArrayList<Object>(List.of(reason)), "evaluated", new ArrayList<Object>(List.of(row)));
    }

    /** Evaluates EVERY invariant (no short-circuit) against the action and the running state. Pure, total, fail closed: {@code {ok, violated, reasons, evaluated}}. */
    public static Map<String, Object> checkProhibitions(Object action, Object constitution, Object state) {
        return SafeRegex.withBudget(() -> checkInner(action, constitution, state));
    }

    private static Map<String, Object> checkInner(Object action, Object constitution, Object state) {
        try {
            List<String> cp = validateConstitution(constitution);
            if (!cp.isEmpty()) return structural("<constitution>", cp.get(0));
            if (!actionOk(action)) return structural("<action>", "malformed action");
            String sp = stateProblem(state);
            if (sp != null) return structural("<state>", sp);
            List<Object> evaluated = new ArrayList<>();
            for (Object invO : arr(obj(constitution).get("invariants"))) {
                Map<String, Object> inv = obj(invO);
                Map<String, Object> r;
                try {
                    r = evalOne(inv, obj(action), obj(state));
                } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
                    r = bad("evaluation error (fail closed)");
                }
                Map<String, Object> row = map("id", inv.get("id"), "kind", inv.get("kind"), "result", Boolean.TRUE.equals(r.get("ok")) ? "pass" : "violated");
                if (truthy(r.get("reason"))) row.put("reason", r.get("reason"));
                evaluated.add(row);
            }
            return summarize(evaluated);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return structural("<monitor>", "monitor error (fail closed)");
        }
    }

    /** {@code {ok, violated, reasons, evaluated}} of a list of result rows. */
    static Map<String, Object> summarize(List<Object> evaluated) {
        List<Object> violated = new ArrayList<>(), reasons = new ArrayList<>();
        for (Object e : evaluated) {
            Map<String, Object> row = obj(e);
            if (!"violated".equals(row.get("result"))) continue;
            violated.add(row.get("id"));
            reasons.add(text(row.get("id")) + ": " + (row.containsKey("reason") ? text(row.get("reason")) : "violated"));
        }
        return map("ok", violated.isEmpty(), "violated", violated, "reasons", reasons, "evaluated", evaluated);
    }

    private static Object sumAmount(Object a, Object b) { return jn(dv(a) + dv(b)); }

    /** Pure state transition for an ADMITTED action: {@code {ok, state}} or {@code {ok: false, reason}}; never throws. {@code now} null = the state's own. */
    public static Map<String, Object> advanceStateStrict(Object action, Object constitution, Object state, Object now) {
        return advanceStateStrictRef(action, constitution, state, now == null ? ABSENT : now);
    }

    /** As the reference: {@code now} {@link #ABSENT} = the state's own; an explicit null is a clock regression. */
    static Map<String, Object> advanceStateStrictRef(Object action, Object constitution, Object state, Object now) {
        Object n = now != ABSENT ? now : (state instanceof Map ? obj(state).get("now") : null);
        return SafeRegex.withBudget(() -> advanceInner(action, constitution, state, n));
    }

    private static Map<String, Object> advanceInner(Object action, Object constitution, Object state, Object now) {
        try {
            List<String> cp = validateConstitution(constitution);
            if (!cp.isEmpty()) return bad(cp.get(0));
            String sp = stateProblem(state);
            if (sp != null) return bad(sp);
            if (!fin(now) || dv(now) < dv(obj(state).get("now"))) return bad("clock regression");
            if (!actionOk(action)) return bad("malformed action");
            Map<String, Object> canon = canonicalState(state);
            String prevDigest = Pca.hashCanonical(canon);
            String actionDigest = Pca.hashCanonical(action);
            Map<String, Object> ledger = new LinkedHashMap<>();
            for (Map.Entry<String, Object> en : obj(canon.get("ledger")).entrySet()) ledger.put(en.getKey(), new ArrayList<>(arr(en.getValue())));
            Map<String, Object> latched = new LinkedHashMap<>(obj(canon.get("latched")));
            for (Object invO : arr(obj(constitution).get("invariants"))) {
                Map<String, Object> inv = obj(invO);
                String kind = (String) inv.get("kind"), id = (String) inv.get("id");
                if (kind.equals("cap") || kind.equals("rate")) {
                    List<Object> prev = ledger.containsKey(id) ? arr(ledger.get(id)) : new ArrayList<>();
                    double lo = inv.get("window_secs") == null ? Double.NEGATIVE_INFINITY : dv(now) - dv(inv.get("window_secs")) * 1000;
                    List<Map<String, Object>> kept = new ArrayList<>();
                    for (Object e : prev) if (dv(obj(e).get("t")) > lo) kept.add(obj(e));
                    if (ForbidWins.whenMatches(inv.get("when"), obj(action))) {
                        Object amount = jn(1);
                        if (kind.equals("cap")) {
                            Predicates.Resolved r = Predicates.resolvePath(obj(action), inv.get("amount"));
                            if (!r.found || !fin(r.value) || dv(r.value) < 0) return bad(id + ": amount unresolvable");
                            amount = r.value;
                        }
                        kept.add(map("t", now, "amount", amount));
                    }
                    kept.sort(Prohibitions::cmpEntry);
                    if (kept.size() > MAX_LEDGER) {
                        if (kind.equals("rate")) return bad(id + ": rate ledger overflow");
                        while (kept.size() > MAX_LEDGER) {
                            Map<String, Object> x = kept.get(0), y = kept.get(1); // merge the oldest two; keeps the LATER time => never under-counts a cap
                            kept.subList(0, 2).clear();
                            kept.add(0, map("t", y.get("t"), "amount", sumAmount(x.get("amount"), y.get("amount"))));
                        }
                    }
                    if (!kept.isEmpty()) ledger.put(id, new ArrayList<Object>(kept));
                    else ledger.remove(id);
                } else if (kind.equals("never_after")) {
                    // conservative match: an ambiguous trigger latches (stricter)
                    if (!latched.containsKey(id) && ForbidWins.whenMatches(inv.get("after"), obj(action))) latched.put(id, now);
                } else if (kind.equals("require_prior")) {
                    // AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
                    if (!latched.containsKey(id) && whenAffirmative(inv.get("prior"), obj(action))) latched.put(id, now);
                }
            }
            Map<String, Object> next = map("now", now, "seq", jn(dv(obj(state).get("seq")) + 1),
                "parent", Pca.hashCanonical(map("d", STATE_CHAIN_DOMAIN, "state", prevDigest, "action", actionDigest)), "ledger", ledger, "latched", latched);
            if (stateProblem(next) != null) return bad("resulting state invalid");
            return map("ok", true, "state", next);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return bad("advance error (fail closed)");
        }
    }

    /** Affirmative trigger match (plain permission semantics, unresolvable = not matched). */
    public static boolean whenAffirmative(Object w, Map<String, Object> ctx) {
        try {
            return ForbidWins.validateWhen(w, "when") == null && Predicates.predicateMatches(w, ctx);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return false;
        }
    }

    // ---- per-action safety evidence

    /** The evidence a verifier re-checks. Never throws. */
    public static Map<String, Object> proveSafety(Object action, Object constitution, Object state) {
        return evidenceFrom(checkProhibitions(action, constitution, state), action, constitution, state);
    }

    static Map<String, Object> evidenceFrom(Map<String, Object> r, Object action, Object constitution, Object state) {
        String cid = safe(() -> constitutionId(obj(constitution)));
        String adg = safe(() -> Pca.hashCanonical(action));
        String sdg = safe(() -> stateDigest(state));
        List<Object> extra = new ArrayList<>();
        if (cid.equals(UNHASHABLE)) extra.add("<constitution>");
        if (adg.equals(UNHASHABLE)) extra.add("<action>");
        if (sdg.equals(UNHASHABLE)) extra.add("<state>");
        List<Object> violated = new ArrayList<>(arr(r.get("violated")));
        for (Object x : extra) if (!violated.contains(x)) violated.add(x);
        List<Object> evaluated = new ArrayList<>();
        for (Object e : arr(r.get("evaluated"))) evaluated.add(new LinkedHashMap<>(obj(e)));
        Object now = state instanceof Map && fin(obj(state).get("now")) ? obj(state).get("now") : jn(0);
        return map("v", jn(EVIDENCE_VERSION), "constitution", cid, "action_digest", adg, "state_digest", sdg, "now", now, "evaluated", evaluated,
            "ok", Boolean.TRUE.equals(r.get("ok")) && extra.isEmpty(), "violated", violated);
    }

    /** Recomputes the monitor and requires the evidence to match EXACTLY. Null when it does, else the reason. Never throws. */
    public static String verifySafetyEvidence(Object evidence, Object action, Object constitution, Object state) {
        try {
            if (!isObj(evidence) || !isInteger(obj(evidence).get("v")) || dv(obj(evidence).get("v")) != EVIDENCE_VERSION) return "unsupported evidence version";
            Map<String, Object> ev = obj(evidence);
            Map<String, Object> fresh = proveSafety(action, constitution, state);
            if (!fresh.get("constitution").equals(ev.get("constitution"))) return "constitution mismatch";
            if (!fresh.get("action_digest").equals(ev.get("action_digest"))) return "action digest mismatch";
            if (!fresh.get("state_digest").equals(ev.get("state_digest"))) return "state digest mismatch";
            if (!Pca.hashCanonical(fresh).equals(Pca.hashCanonical(ev))) return "evidence does not reproduce";
            if (!Boolean.TRUE.equals(fresh.get("ok"))) return "prohibition violated: " + joinIds(arr(fresh.get("violated")));
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return "verification error (fail closed)";
        }
    }

    static String joinIds(List<Object> l) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < l.size(); i++) b.append(i == 0 ? "" : ",").append(text(l.get(i)));
        return b.toString();
    }

    public static final String SAFETY_EVIDENCE_SIG_DOMAIN = "atlas-pca/safety-evidence/v1\u0000";

    /** The id the signer commits to: a hash of the evidence and the three digests it binds. */
    public static String safetyBindingId(Map<String, Object> evidence, String signer) {
        // a missing bound digest is undefined in the reference and does not canonicalize: throw, never hash a null in its place
        for (String k : new String[] {"constitution", "action_digest", "state_digest"}) if (!evidence.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        return Pca.hashCanonical(map("d", SAFETY_EVIDENCE_SIG_DOMAIN, "signer", signer, "evidence", Pca.hashCanonical(evidence),
            "constitution", evidence.get("constitution"), "action_digest", evidence.get("action_digest"), "state_digest", evidence.get("state_digest")));
    }

    /** Signs evidence (it must be bound to real digests). Throws {@link IllegalArgumentException} otherwise. */
    public static Map<String, Object> signSafetyEvidence(Object evidence, byte[] signerSeed, String signerPublic) {
        if (!isObj(evidence) || !isInteger(obj(evidence).get("v")) || dv(obj(evidence).get("v")) != EVIDENCE_VERSION) throw new IllegalArgumentException("signSafetyEvidence: unsupported evidence");
        Map<String, Object> ev = obj(evidence);
        for (String k : new String[] {"constitution", "action_digest", "state_digest"}) {
            Object d = ev.get(k);
            if (!(d instanceof String) || ((String) d).isEmpty() || UNHASHABLE.equals(d)) throw new IllegalArgumentException("signSafetyEvidence: unbound evidence");
        }
        if (signerPublic == null || signerPublic.isEmpty()) throw new IllegalArgumentException("signSafetyEvidence: signer missing");
        String id = safetyBindingId(ev, signerPublic);
        return map("evidence", ev, "signer", signerPublic, "id", id, "sig", Pca.b64(Keys.edFromSeed(signerSeed).sign(domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, id))));
    }

    /** JavaScript {@code Array.prototype.join(',')}: null and undefined read as the empty string. */
    private static String jsJoin(List<Object> l) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < l.size(); i++) b.append(i == 0 ? "" : ",").append(l.get(i) == null ? "" : text(l.get(i)));
        return b.toString();
    }

    private static String no(String reason) { return reason; }

    /**
     * Verifies signed evidence offline: the signer pinned, the binding id, the signature, the bound digests, internal consistency and (when action,
     * constitution and state are all given) a full recomputation. {@code expected} carries {@code signer} (a key or a list), {@code action} or
     * {@code actionDigest}, {@code constitution} or {@code constitutionId}, {@code state} or {@code stateDigest}, optional {@code principal} and
     * {@code requireOk}. Null when it verifies, else the exact reason. Reads properties with JavaScript semantics and never throws.
     */
    public static String verifySignedSafetyEvidence(Object signedO, Object expectedO) {
        try {
            if (!isObj(signedO) || !isObj(obj(signedO).get("evidence")) || !isObj(expectedO)) return no("malformed input");
            Map<String, Object> signed = obj(signedO), expected = obj(expectedO), ev = obj(signed.get("evidence"));
            if (!isInteger(ev.get("v")) || dv(ev.get("v")) != EVIDENCE_VERSION) return no("unsupported evidence version");
            List<Object> signers = expected.get("signer") instanceof List ? arr(expected.get("signer")) : new ArrayList<>(Arrays.asList(get(expected, "signer")));
            boolean badSigner = signers.isEmpty();
            for (Object sg : signers) if (!(sg instanceof String) || ((String) sg).isEmpty()) badSigner = true;
            if (badSigner) return no("no pinned signer");
            if (!(signed.get("signer") instanceof String) || !signers.contains(signed.get("signer"))) return no("signer not trusted");
            boolean hasAction = expected.containsKey("action"), hasConst = expected.containsKey("constitution"), hasState = expected.containsKey("state");
            if (!hasAction && !expected.containsKey("actionDigest")) return no("unbound: action not specified");
            if (!hasConst && !expected.containsKey("constitutionId")) return no("unbound: constitution not specified");
            if (!hasState && !expected.containsKey("stateDigest")) return no("unbound: state not specified");
            if (!(signed.get("id") instanceof String) || !signed.get("id").equals(safetyBindingId(ev, (String) signed.get("signer")))) return no("binding id mismatch");
            if (!(signed.get("sig") instanceof String) || !IntentJs.verifyEd(signed.get("signer"), domainMessage(SAFETY_EVIDENCE_SIG_DOMAIN, (String) signed.get("id")), signed.get("sig"))) return no("bad signature");

            Object wantAction = hasAction ? Pca.hashCanonical(expected.get("action")) : expected.get("actionDigest");
            if (hasAction && expected.containsKey("actionDigest") && !java.util.Objects.equals(expected.get("actionDigest"), wantAction)) return no("expected action and digest disagree");
            if (!java.util.Objects.equals(ev.get("action_digest"), wantAction)) return no("action digest mismatch (evidence bound to another action)");

            if (expected.containsKey("principal")) {
                Object sc = expected.get("constitution");
                if (!isObj(sc) || !(obj(sc).get("sig") instanceof String)) return no("principal pin requires a signed constitution");
                String vc = verifyConstitution(sc, expected.get("principal") instanceof String ? (String) expected.get("principal") : "\u0000no-principal");
                if (vc != null) return no("constitution not authentic: " + vc);
            }
            Object wantConst = hasConst ? constitutionId(obj(expected.get("constitution"))) : expected.get("constitutionId");
            if (hasConst && expected.containsKey("constitutionId") && !java.util.Objects.equals(expected.get("constitutionId"), wantConst)) return no("expected constitution and id disagree");
            if (!java.util.Objects.equals(ev.get("constitution"), wantConst)) return no("constitution mismatch (evidence bound to another constitution)");
            // a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row (undefined === undefined)
            if (hasConst) {
                List<String> cp = validateConstitution(expected.get("constitution"));
                if (!cp.isEmpty()) return no("constitution malformed: " + cp.get(0));
            }

            Object wantState = hasState ? stateDigest(expected.get("state")) : expected.get("stateDigest");
            if (hasState && expected.containsKey("stateDigest") && !java.util.Objects.equals(expected.get("stateDigest"), wantState)) return no("expected state and digest disagree");
            if (!java.util.Objects.equals(ev.get("state_digest"), wantState)) return no("state digest mismatch (evidence bound to another state)");

            // internal consistency: the claimed verdict must follow from the claimed rows
            if (!(ev.get("evaluated") instanceof List) || !(ev.get("violated") instanceof List)) return no("malformed evidence");
            List<Object> rows = arr(ev.get("evaluated")), violated = arr(ev.get("violated"));
            for (Object r : rows) if (isObj(r) && obj(r).containsKey("id") && !(obj(r).get("id") instanceof String)) return no("malformed evidence");
            int badRows = 0;
            for (Object r : rows) if (!(isObj(r) && "pass".equals(obj(r).get("result")))) badRows++;
            if (!Boolean.valueOf(badRows == 0 && violated.isEmpty()).equals(ev.get("ok"))) return no("evidence verdict inconsistent with rows");

            if (hasAction && hasConst && hasState) {
                String full = verifySafetyEvidence(ev, expected.get("action"), expected.get("constitution"), expected.get("state"));
                if (full != null && Boolean.TRUE.equals(ev.get("ok"))) return no(full);
                if (full != null && !Boolean.TRUE.equals(ev.get("ok")) && !full.startsWith("prohibition violated")) return no(full);
            } else if (Boolean.TRUE.equals(ev.get("ok")) && hasConst) {
                List<Object> inv = arr(obj(expected.get("constitution")).get("invariants"));
                List<Object> ids = new ArrayList<>();
                for (Object i : inv) ids.add(prop(i, "id"));
                boolean covered = rows.size() == ids.size();
                for (int i = 0; covered && i < rows.size(); i++) {
                    if (rows.get(i) == null) throw new IllegalStateException("cannot read properties of null");
                    if (!java.util.Objects.equals(prop(rows.get(i), "id"), ids.get(i))) covered = false;
                }
                if (!covered) return no("evidence does not cover every invariant");
            }
            if (!Boolean.FALSE.equals(expected.get("requireOk")) && !Boolean.TRUE.equals(ev.get("ok"))) return no("prohibition violated: " + jsJoin(violated));
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return no("verification error (fail closed)");
        }
    }

    // ---- composition: permissions grant, prohibitions veto

    /** The pure kernel of the server's critical section: CAS guards, compose, evidence over the pre-state, next state on allow. {@code expectedSeq} / {@code expectedStateDigest} are nullable. */
    public static Map<String, Object> checkAndAdvance(boolean permitted, Object action, Object constitution, Object state, Object expectedSeq, String expectedStateDigest) {
        return checkAndAdvanceRef(permitted, action, constitution, state, expectedSeq == null ? ABSENT : expectedSeq, expectedStateDigest);
    }

    /** As the reference: {@code expectedSeq} {@link #ABSENT} = no check; an explicit null is a stale head. */
    static Map<String, Object> checkAndAdvanceRef(boolean permitted, Object action, Object constitution, Object state, Object expectedSeq, String expectedStateDigest) {
        Map<String, Object> monitored = checkProhibitions(action, constitution, state);
        Map<String, Object> evidence = evidenceFrom(monitored, action, constitution, state);
        boolean ok = Boolean.TRUE.equals(monitored.get("ok"));
        boolean allow = permitted && ok;
        String decidedBy = !ok ? "prohibition" : (permitted ? "none" : "permission");
        try {
            if (expectedSeq != ABSENT && (!isObj(state) || !jsonNumEq(obj(state).get("seq"), expectedSeq))) return refuse(state, evidence, monitored, "state", "stale state head (seq)");
            if (expectedStateDigest != null && !expectedStateDigest.equals(safe(() -> stateDigest(state)))) return refuse(state, evidence, monitored, "state", "stale state head (digest)");
            if (!allow) return refuse(state, evidence, monitored, decidedBy.equals("none") ? "permission" : decidedBy, null);
            if (!Boolean.TRUE.equals(evidence.get("ok"))) return refuse(state, evidence, monitored, "prohibition", "evidence not attestable");
            Map<String, Object> adv = advanceStateStrictRef(action, constitution, state, ABSENT);
            if (!Boolean.TRUE.equals(adv.get("ok"))) return refuse(state, evidence, monitored, "state", "advance failed: " + adv.get("reason"));
            return map("allow", true, "decidedBy", "none", "evidence", evidence, "prohibition", monitored, "next", adv.get("state"));
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return refuse(state, evidence, monitored, "state", "check-and-advance error (fail closed)");
        }
    }

    private static boolean jsonNumEq(Object a, Object b) {
        Double x = Caveats.fin(a), y = Caveats.fin(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue(); // JavaScript ===: -0 equals 0
    }

    private static Map<String, Object> refuse(Object state, Map<String, Object> evidence, Map<String, Object> monitored, String decidedBy, String reason) {
        Map<String, Object> out = map("allow", false, "decidedBy", decidedBy, "evidence", evidence, "prohibition", monitored, "next", state);
        if (reason != null && !reason.isEmpty()) out.put("reason", reason);
        return out;
    }
}
