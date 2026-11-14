package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bounded safety-LTL behavioural contracts (the reference's {@code contracts.ts}): an optional embedded prohibition constitution ({@code invariants}) plus
 * temporal {@code clauses} (always, never, precedes, requires_prior, responds_within, and) over ONE shared, hash-chained {@link Prohibitions} state. A
 * contract without clauses behaves exactly like the prohibition monitor. Everything malformed, unknown or unresolvable fails closed; nothing here throws.
 */
public final class Contracts {
    private Contracts() {}

    public static final int CONTRACT_VERSION = 1;
    public static final String CONTRACT_SIG_DOMAIN = "atlas-pca/contract/v1\u0000";
    public static final int MAX_CLAUSES = 256;
    public static final int MAX_CLAUSE_DEPTH = 16;

    private static List<String> one(String s) { return new ArrayList<>(List.of(s)); }

    /** Structural problems with a clause (empty = well formed); collects ids into {@code seen} for global uniqueness. */
    static List<String> validateClause(Object clO, Set<String> seen, int depth) {
        if (depth > MAX_CLAUSE_DEPTH) return one("clause nesting too deep");
        if (!Prohibitions.isObj(clO)) return one("clause not an object");
        Map<String, Object> cl = Prohibitions.obj(clO);
        Object rawId = cl.get("id");
        if (!(rawId instanceof String) || ((String) rawId).isEmpty()) return one("<no id>: missing clause id");
        String id = (String) rawId;
        if (id.length() > Prohibitions.MAX_ID_LEN) return one(id + ": id too long");
        if (Prohibitions.FORBIDDEN_IDS.contains(id)) return one(id + ": forbidden id");
        if (seen.contains(id)) return one(id + ": duplicate id");
        seen.add(id);
        Object kind = Prohibitions.get(cl, "kind");
        String e;
        if ("always".equals(kind) || "never".equals(kind)) {
            e = ForbidWins.validateWhen(cl.get("p"), "p");
            return e != null ? one(id + ": " + e) : new ArrayList<>();
        }
        if ("precedes".equals(kind) || "requires_prior".equals(kind) || "responds_within".equals(kind)) {
            e = ForbidWins.validateWhen(cl.get("p"), "p");
            if (e == null) e = ForbidWins.validateWhen(cl.get("q"), "q");
            if (e != null) return one(id + ": " + e);
            if ("responds_within".equals(kind)) {
                Object within = cl.get("within");
                if (!Prohibitions.isInteger(within) || Prohibitions.dv(within) < 1 || Prohibitions.dv(within) > Prohibitions.MAX_DEADLINE) {
                    return one(id + ": within must be an integer in [1, MAX_DEADLINE]");
                }
            }
            return new ArrayList<>();
        }
        if ("and".equals(kind)) {
            Object subs = cl.get("clauses");
            if (!(subs instanceof List) || ((List<?>) subs).isEmpty()) return one(id + ": and.clauses must be a non-empty array");
            List<String> out = new ArrayList<>();
            for (Object sub : (List<?>) subs) out.addAll(validateClause(sub, seen, depth + 1));
            return out;
        }
        return one(id + ": unknown clause kind " + Prohibitions.text(kind));
    }

    private static int countClauses(List<Object> cls, int depth) {
        // bounded recursion: an absurdly deep nest is "too many" at once (validateClause then reports the depth)
        if (depth > MAX_CLAUSE_DEPTH + 1) return MAX_CLAUSES + 1;
        int n = 0;
        for (Object cl : cls) {
            n++;
            if (Prohibitions.isObj(cl) && "and".equals(Prohibitions.obj(cl).get("kind")) && Prohibitions.obj(cl).get("clauses") instanceof List) {
                n += countClauses(Prohibitions.arr(Prohibitions.obj(cl).get("clauses")), depth + 1);
            }
        }
        return n;
    }

    /** Structural problems with a contract (empty = well formed). Total. */
    public static List<String> validateContract(Object cO) {
        if (!Prohibitions.isObj(cO)) return one("contract not an object");
        Map<String, Object> c = Prohibitions.obj(cO);
        List<String> out = new ArrayList<>();
        Object version = c.get("version");
        if (!(Prohibitions.fin(version) && Prohibitions.dv(version) == CONTRACT_VERSION)) out.add("unsupported version " + Prohibitions.text(Prohibitions.get(c, "version")));
        if (!(c.get("principal") instanceof String) || ((String) c.get("principal")).isEmpty()) out.add("principal missing");
        Set<String> ids = new HashSet<>();
        if (c.containsKey("invariants")) {
            Object invariants = c.get("invariants");
            if (!(invariants instanceof List)) {
                out.add("invariants not an array");
                return out;
            }
            List<Object> l = Prohibitions.arr(invariants);
            if (l.size() > Prohibitions.MAX_INVARIANTS) out.add("too many invariants");
            for (Object inv : l) {
                out.addAll(Prohibitions.validateInvariant(inv));
                Object id = Prohibitions.isObj(inv) ? Prohibitions.obj(inv).get("id") : null;
                if (id instanceof String) {
                    if (ids.contains(id)) out.add(id + ": duplicate id");
                    ids.add((String) id);
                }
            }
        }
        if (c.containsKey("clauses")) {
            Object clauses = c.get("clauses");
            if (!(clauses instanceof List)) {
                out.add("clauses not an array");
                return out;
            }
            List<Object> l = Prohibitions.arr(clauses);
            if (countClauses(l, 1) > MAX_CLAUSES) out.add("too many clauses");
            // clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
            for (Object cl : l) out.addAll(validateClause(cl, ids, 1));
        }
        return out;
    }

    // ---- commitment

    public static String contractId(Map<String, Object> c) { return Pca.hashCanonical(Prohibitions.body(c)); }

    /** Signs a contract with the principal's Ed25519 seed. Throws {@link IllegalArgumentException} on an invalid contract. */
    public static Map<String, Object> signContract(Map<String, Object> c, byte[] principalSeed) {
        List<String> problems = validateContract(c);
        if (!problems.isEmpty()) throw new IllegalArgumentException("signContract: " + String.join("; ", problems));
        String id = contractId(c);
        Map<String, Object> out = Prohibitions.body(c);
        out.put("id", id);
        out.put("sig", Pca.b64(Keys.edFromSeed(principalSeed).sign(Prohibitions.domainMessage(CONTRACT_SIG_DOMAIN, id))));
        return out;
    }

    /** Well formed, id matches content, signature by {@code expectedPrincipal} (or the embedded one). Null when it verifies, else the reason. Never throws. */
    public static String verifyContract(Object sc, String expectedPrincipal) {
        try {
            List<String> problems = validateContract(sc);
            if (!problems.isEmpty()) return problems.get(0);
            Map<String, Object> c = Prohibitions.obj(sc);
            if (expectedPrincipal != null && !expectedPrincipal.equals(c.get("principal"))) return "principal mismatch";
            if (!(c.get("id") instanceof String) || !c.get("id").equals(contractId(c))) return "id does not match content";
            if (!(c.get("sig") instanceof String) || !IntentJs.verifyEd(c.get("principal"), Prohibitions.domainMessage(CONTRACT_SIG_DOMAIN, (String) c.get("id")), c.get("sig"))) return "bad signature";
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return "verification error (fail closed)";
        }
    }

    static Map<String, Object> embeddedConstitution(Map<String, Object> c) {
        return Prohibitions.map("version", Prohibitions.jn(1), "principal", c.get("principal"),
            "invariants", c.get("invariants") instanceof List ? c.get("invariants") : new ArrayList<Object>());
    }

    // ---- clause evaluation

    private static Map<String, Object> row(Map<String, Object> cl, boolean ok, Object reason) {
        Map<String, Object> r = Prohibitions.map("id", cl.get("id"), "kind", cl.get("kind"), "result", ok ? "pass" : "violated");
        if (Prohibitions.truthy(reason)) r.put("reason", reason);
        return r;
    }

    private static Map<String, Object> base(Map<String, Object> cl, boolean ok, Object reason) {
        Map<String, Object> t = Prohibitions.map("ok", ok, "rows", new ArrayList<Object>(List.of(row(cl, ok, reason))),
            "latchSet", new LinkedHashMap<String, Object>(), "deadlineSet", new LinkedHashMap<String, Object>());
        if (Prohibitions.truthy(reason)) t.put("reason", reason);
        return t;
    }

    private static Object desc(Map<String, Object> cl, String dflt) {
        Object d = cl.get("description");
        return d == null ? dflt : d;
    }

    /** The per-clause transition: the verdict plus the intended latch / deadline updates (applied only if the whole contract is ok). */
    static Map<String, Object> evalClause(Map<String, Object> cl, Map<String, Object> ctx, Map<String, Object> state, Object now) {
        Map<String, Object> latched = Prohibitions.obj(state.get("latched"));
        Map<String, Object> deadlines = state.get("deadlines") instanceof Map ? Prohibitions.obj(state.get("deadlines")) : new LinkedHashMap<>();
        try {
            String kind = (String) cl.get("kind");
            switch (kind) {
                case "always":
                    return Prohibitions.whenAffirmative(cl.get("p"), ctx) ? base(cl, true, null) : base(cl, false, desc(cl, "always-invariant violated (action does not satisfy p)"));
                case "never":
                    return ForbidWins.whenMatches(cl.get("p"), ctx) ? base(cl, false, desc(cl, "never-invariant violated (forbidden action)")) : base(cl, true, null);
                case "precedes":
                case "requires_prior": {
                    boolean isQ = ForbidWins.whenMatches(cl.get("q"), ctx); // the guarded action, conservative
                    boolean held = latched.containsKey(cl.get("id"));
                    boolean ok = !isQ || held;
                    Map<String, Object> t = base(cl, ok, ok ? null : desc(cl, "precedence violated (prerequisite p not yet admitted before q)"));
                    // latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
                    if (!held && Prohibitions.whenAffirmative(cl.get("p"), ctx)) Prohibitions.obj(t.get("latchSet")).put((String) cl.get("id"), now);
                    return t;
                }
                case "responds_within": {
                    boolean violated = false;
                    Object carried = null;
                    if (deadlines.containsKey(cl.get("id"))) {
                        double cur = Prohibitions.dv(deadlines.get(cl.get("id")));
                        if (Prohibitions.whenAffirmative(cl.get("q"), ctx)) {
                            carried = null; // any response discharges all open obligations
                        } else {
                            double r = cur - 1;
                            if (r <= 0) violated = true; // the window is exhausted with no response: a violation at this action
                            else carried = Prohibitions.jn(r);
                        }
                    }
                    if (violated) {
                        Object reason = desc(cl, "bounded-liveness deadline missed (no q within " + Prohibitions.text(cl.get("within")) + " actions of p)");
                        Map<String, Object> rw = row(cl, false, reason);
                        return Prohibitions.map("ok", false, "reason", rw.get("reason"), "rows", new ArrayList<Object>(List.of(rw)),
                            "latchSet", new LinkedHashMap<String, Object>(), "deadlineSet", new LinkedHashMap<String, Object>());
                    }
                    Object nxt = carried;
                    if (ForbidWins.whenMatches(cl.get("p"), ctx)) {
                        nxt = nxt == null ? cl.get("within") : (Prohibitions.dv(nxt) <= Prohibitions.dv(cl.get("within")) ? nxt : cl.get("within"));
                    }
                    Map<String, Object> ds = new LinkedHashMap<>();
                    ds.put((String) cl.get("id"), nxt);
                    return Prohibitions.map("ok", true, "rows", new ArrayList<Object>(List.of(row(cl, true, null))), "latchSet", new LinkedHashMap<String, Object>(), "deadlineSet", ds);
                }
                case "and": {
                    List<Object> rows = new ArrayList<>();
                    Map<String, Object> latchSet = new LinkedHashMap<>(), deadlineSet = new LinkedHashMap<>();
                    boolean ok = true;
                    Object reason = null;
                    for (Object sub : Prohibitions.arr(cl.get("clauses"))) {
                        Map<String, Object> r = evalClause(Prohibitions.obj(sub), ctx, state, now);
                        rows.addAll(Prohibitions.arr(r.get("rows")));
                        latchSet.putAll(Prohibitions.obj(r.get("latchSet")));
                        deadlineSet.putAll(Prohibitions.obj(r.get("deadlineSet")));
                        if (!Boolean.TRUE.equals(r.get("ok")) && ok) {
                            ok = false;
                            reason = r.get("reason");
                        }
                    }
                    Map<String, Object> out = Prohibitions.map("ok", ok, "rows", rows, "latchSet", latchSet, "deadlineSet", deadlineSet);
                    if (Prohibitions.truthy(reason)) out.put("reason", reason);
                    return out;
                }
                default:
                    return base(cl, false, "unknown clause kind (fail closed)");
            }
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return base(cl, false, "clause evaluation error (fail closed)");
        }
    }

    // ---- the contract monitor

    /** Evaluates a whole contract (embedded constitution + temporal clauses) against one action, WITHOUT advancing: {@code {ok, violated, reasons, evaluated}}. Total, fail closed. */
    public static Map<String, Object> checkContract(Object action, Object contract, Object state) {
        return SafeRegex.withBudget(() -> checkInner(action, contract, state));
    }

    private static Map<String, Object> checkInner(Object action, Object contract, Object state) {
        try {
            List<String> cp = validateContract(contract);
            if (!cp.isEmpty()) return structural("<contract>", cp.get(0));
            if (!Prohibitions.actionOk(action)) return structural("<action>", "malformed action");
            String sp = Prohibitions.stateProblem(state);
            if (sp != null) return structural("<state>", sp);
            List<Object> evaluated = new ArrayList<>();
            Map<String, Object> c = Prohibitions.obj(contract);
            Map<String, Object> constitution = embeddedConstitution(c);
            if (!Prohibitions.arr(constitution.get("invariants")).isEmpty()) evaluated.addAll(Prohibitions.arr(Prohibitions.checkProhibitions(action, constitution, state).get("evaluated")));
            Object now = Prohibitions.obj(state).get("now");
            if (c.get("clauses") instanceof List) {
                for (Object clO : Prohibitions.arr(c.get("clauses"))) {
                    Map<String, Object> cl = Prohibitions.obj(clO);
                    try {
                        evaluated.addAll(Prohibitions.arr(evalClause(cl, Prohibitions.obj(action), Prohibitions.obj(state), now).get("rows")));
                    } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
                        evaluated.add(Prohibitions.map("id", cl.get("id"), "kind", cl.get("kind") == null ? "clause" : cl.get("kind"), "result", "violated", "reason", "clause evaluation error (fail closed)"));
                    }
                }
            }
            return Prohibitions.summarize(evaluated);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return structural("<monitor>", "monitor error (fail closed)");
        }
    }

    /** A structural failure: the reason is reported under the id ({@code <id>: reason}). */
    private static Map<String, Object> structural(String id, String reason) {
        Map<String, Object> r = Prohibitions.structural(id, reason);
        r.put("reasons", new ArrayList<Object>(List.of(id + ": " + reason)));
        return r;
    }

    private static Map<String, Object> refuse(Object state, Object action, Object contract, String decidedBy, Map<String, Object> r, String reason) {
        Map<String, Object> base = r != null ? r : checkContract(action, contract, state);
        List<Object> violated = new ArrayList<>(Prohibitions.arr(base.get("violated")));
        List<Object> reasons = new ArrayList<>(Prohibitions.arr(base.get("reasons")));
        if (reason != null) {
            violated.removeIf(v -> "<state>".equals(v));
            violated.add("<state>");
            reasons.add("<state>: " + reason);
        }
        return Prohibitions.map("ok", false, "violated", violated, "reasons", reasons, "evaluated", base.get("evaluated"), "next", state, "decidedBy", decidedBy);
    }

    /**
     * Checks the whole contract against one action and, iff it holds, advances the hash-chained monitor state. {@code now} (nullable: the state's own),
     * {@code expectedSeq} and {@code expectedStateDigest} (nullable) are the options. Fail closed; {@code next} is the input state unless {@code ok}.
     */
    public static Map<String, Object> advanceContract(Object state, Object action, Object contract, Object nowOpt, Object expectedSeq, String expectedStateDigest) {
        try {
            Object now = nowOpt != null ? nowOpt : (state instanceof Map ? Prohibitions.obj(state).get("now") : null);
            // CAS on the chain head FIRST: a rolled-back / stale state is refused before anything else
            if (expectedSeq != null && (!Prohibitions.isObj(state) || !Prohibitions.fin(Prohibitions.obj(state).get("seq")) || Prohibitions.dv(Prohibitions.obj(state).get("seq")) != Prohibitions.dv(expectedSeq))) {
                return refuse(state, action, contract, "state", null, "stale state head (seq)");
            }
            if (expectedStateDigest != null && !expectedStateDigest.equals(Prohibitions.safe(() -> Prohibitions.stateDigest(state)))) {
                return refuse(state, action, contract, "state", null, "stale state head (digest)");
            }
            Map<String, Object> verdict = checkContract(action, contract, state);
            if (!Boolean.TRUE.equals(verdict.get("ok"))) {
                boolean structural = false;
                for (Object v : Prohibitions.arr(verdict.get("violated"))) {
                    String s = Prohibitions.text(v);
                    if (s.startsWith("<") && s.endsWith(">")) structural = true;
                }
                Map<String, Object> out = new LinkedHashMap<>(verdict);
                out.put("next", state);
                out.put("decidedBy", structural ? "state" : "contract");
                return out;
            }
            Map<String, Object> c = Prohibitions.obj(contract);
            Map<String, Object> constitution = embeddedConstitution(c);
            Map<String, Object> adv = Prohibitions.advanceStateStrict(action, constitution, state, now);
            if (!Boolean.TRUE.equals(adv.get("ok"))) return refuse(state, action, contract, "state", verdict, "advance failed: " + adv.get("reason"));
            Map<String, Object> advState = Prohibitions.obj(adv.get("state"));
            Map<String, Object> latched = new LinkedHashMap<>(Prohibitions.obj(advState.get("latched")));
            Map<String, Object> deadlines = new LinkedHashMap<>(Prohibitions.obj(state).get("deadlines") instanceof Map ? Prohibitions.obj(Prohibitions.obj(state).get("deadlines")) : new LinkedHashMap<>());
            final Object nowF = now;
            SafeRegex.withBudget(() -> {
                if (c.get("clauses") instanceof List) {
                    for (Object clO : Prohibitions.arr(c.get("clauses"))) {
                        Map<String, Object> t = evalClause(Prohibitions.obj(clO), Prohibitions.obj(action), Prohibitions.obj(state), nowF);
                        for (Map.Entry<String, Object> e : Prohibitions.obj(t.get("latchSet")).entrySet()) if (!latched.containsKey(e.getKey())) latched.put(e.getKey(), e.getValue());
                        for (Map.Entry<String, Object> e : Prohibitions.obj(t.get("deadlineSet")).entrySet()) {
                            if (e.getValue() == null) deadlines.remove(e.getKey());
                            else deadlines.put(e.getKey(), e.getValue());
                        }
                    }
                }
                return null;
            });
            Map<String, Object> next = new LinkedHashMap<>(advState);
            next.put("latched", latched);
            if (!deadlines.isEmpty()) next.put("deadlines", deadlines);
            String sp = Prohibitions.stateProblem(next);
            if (sp != null) return refuse(state, action, contract, "state", verdict, "resulting state invalid: " + sp);
            Map<String, Object> out = new LinkedHashMap<>(verdict);
            out.put("next", next);
            out.put("decidedBy", "none");
            return out;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return refuse(state, action, contract, "state", null, "advance error (fail closed)");
        }
    }

    /** {@code allow = permitted AND contract.ok}; on allow the state advances. The contract monitor runs unconditionally. */
    public static Map<String, Object> checkAndAdvanceContract(boolean permitted, Object state, Object action, Object contract, Object nowOpt, Object expectedSeq, String expectedStateDigest) {
        Map<String, Object> adv = advanceContract(state, action, contract, nowOpt, expectedSeq, expectedStateDigest);
        if (!Boolean.TRUE.equals(adv.get("ok"))) {
            Map<String, Object> out = new LinkedHashMap<>(adv);
            out.put("allow", false);
            out.put("permitted", permitted);
            return out;
        }
        if (!permitted) {
            List<Object> reasons = new ArrayList<>(Prohibitions.arr(adv.get("reasons")));
            reasons.add("<permission>: not permitted");
            return Prohibitions.map("ok", false, "violated", adv.get("violated"), "reasons", reasons, "evaluated", adv.get("evaluated"), "next", state,
                "decidedBy", "contract", "allow", false, "permitted", false);
        }
        Map<String, Object> out = new LinkedHashMap<>(adv);
        out.put("allow", true);
        out.put("permitted", true);
        return out;
    }
}
