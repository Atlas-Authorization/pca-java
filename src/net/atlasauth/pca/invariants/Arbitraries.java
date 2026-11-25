package net.atlasauth.pca.invariants;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;

/**
 * Generators of WELL-FORMED random inputs for the PCA core, driven by a seeded {@link Rng} (the same shapes as the reference's
 * property-test arbitraries): Ed25519 seeds, multi-hop chain models whose every hop legally attenuates, predicates, action and caveat
 * contexts, risk policies / inputs / budgets. Everything is plain data fed to the real core; nothing re-implements the model it checks.
 * Caveat contexts use the native snake_case member names ({@code blast_radius}, {@code recent_action_times}, ...).
 */
public final class Arbitraries {
    private Arbitraries() {}

    private static final List<String> VERBS = List.of("read", "write", "delete", "transfer", "list", "admin");
    private static final List<String> RESOURCES = List.of("/acct/a", "/acct/b", "/docs/1", "/docs/2", "/x/y", "/");
    private static final List<String> LEAF_OPS = List.of("eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists");
    private static final List<String> LEAF_FIELDS = List.of("subject.role", "subject.tier", "env.ip", "action.verb", "action.resource", "action.params.amount");
    private static final List<String> REVERSIBILITY = List.of("reversible", "rate_limited", "irreversible", "teleport");

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    // ---- keys ----------------------------------------------------------------------------------------------------

    /** 32 random bytes: a reproducible Ed25519 secret seed. */
    public static byte[] seed32(Rng r) { return r.bytes(32); }

    public static Invariants.GenKeyPair keyPair(Rng r) { return Invariants.keyPairFromSeed(seed32(r)); }

    // ---- predicates ----------------------------------------------------------------------------------------------

    public static String verb(Rng r) { return r.pick(VERBS); }

    public static String resource(Rng r) { return r.bool() ? r.pick(RESOURCES) : r.string(0, 10); }

    /** A known-operator leaf comparison (so a generated leaf is a decidable, well-formed condition). */
    public static Map<String, Object> leafCondition(Rng r) {
        Object value;
        switch ((int) r.integer(0, 3)) {
            case 0: value = r.string(0, 10); break;
            case 1: value = r.integer(-10, 10); break;
            case 2: value = r.bool(); break;
            default: {
                List<Object> l = new ArrayList<>();
                for (long i = r.integer(0, 3); i > 0; i--) l.add(r.string(0, 10));
                value = l;
            }
        }
        return obj("field", r.pick(LEAF_FIELDS), "op", r.pick(LEAF_OPS), "value", value);
    }

    /** A condition: today a known-operator leaf comparison (the reference's {@code arbCondition} is {@code arbLeafCondition}). */
    public static Map<String, Object> condition(Rng r) { return leafCondition(r); }

    public static Map<String, Object> predicate(Rng r) {
        Object verb;
        switch ((int) r.integer(0, 2)) {
            case 0: verb = verb(r); break;
            case 1: {
                List<Object> vs = new ArrayList<>();
                for (long i = r.integer(1, 3); i > 0; i--) vs.add(verb(r));
                verb = vs;
                break;
            }
            default: verb = "*";
        }
        Map<String, Object> p = obj("verb", verb);
        switch ((int) r.integer(0, 4)) {
            case 0: break; // resource absent
            case 1: p.put("resource", "*"); break;
            case 2: p.put("resource", r.pick("/acct/*", "/docs/*")); break;
            default: p.put("resource", resource(r));
        }
        if (r.bool()) {
            List<Object> where = new ArrayList<>();
            for (long i = r.integer(0, 2); i > 0; i--) where.add(leafCondition(r));
            p.put("where", where);
        }
        return p;
    }

    public static List<Object> predicateList(Rng r) {
        List<Object> out = new ArrayList<>();
        for (long i = r.integer(1, 4); i > 0; i--) out.add(predicate(r));
        return out;
    }

    // ---- action + caveat contexts -----------------------------------------------------------------------------------

    public static Map<String, Object> actionContext(Rng r) {
        Map<String, Object> action = obj("verb", verb(r), "resource", resource(r));
        if (r.bool()) {
            Map<String, Object> params = new LinkedHashMap<>();
            for (String k : List.of("amount", "target", "reason")) {
                if (params.size() >= 3 || !r.bool()) continue;
                switch ((int) r.integer(0, 2)) {
                    case 0: params.put(k, r.string(0, 10)); break;
                    case 1: params.put(k, r.integer(-5, 100)); break;
                    default: params.put(k, r.bool());
                }
            }
            action.put("params", params);
        }
        String role = r.pick("admin", "user", "guest");
        long tier = r.integer(0, 5);
        String ip = r.string(0, 10);
        boolean withSubject = r.bool(), withEnv = r.bool();
        Map<String, Object> ctx = obj("action", action);
        if (withSubject) ctx.put("subject", obj("role", role, "tier", tier));
        if (withEnv) ctx.put("env", obj("ip", ip));
        return ctx;
    }

    public static Map<String, Object> caveatContext(Rng r) {
        Map<String, Object> ctx = obj("now", r.integer(0, 10_000_000));
        if (r.bool()) ctx.put("blast_radius", r.real(0, 1));
        if (r.bool()) ctx.put("reversibility_class", r.pick(REVERSIBILITY));
        if (r.bool()) ctx.put("delegation_depth", r.integer(0, 20));
        if (r.bool()) {
            List<Object> times = new ArrayList<>();
            for (long i = r.integer(0, 6); i > 0; i--) times.add(r.integer(0, 10_000_000));
            ctx.put("recent_action_times", times);
        }
        return ctx;
    }

    /** An action context and a caveat context together: one point at which to probe a chain's effective authority. */
    public static Map<String, Object> evalPoint(Rng r) { return obj("action", actionContext(r), "cavCtx", caveatContext(r)); }

    // ---- attenuating delegation chains ----------------------------------------------------------------------------------

    /** A well-formed, built-in, evaluator-decidable caveat spec; {@code budget_frac} becomes a monotone non-increasing allocation. */
    public static Map<String, Object> caveatSpec(Rng r) {
        switch ((int) r.integer(0, 6)) {
            case 0: return obj("k", "expires", "at", r.integer(0, 10_000_000));
            case 1: return obj("k", "not_before", "at", r.integer(0, 10_000_000));
            case 2: return obj("k", "rate", "max", r.integer(1, 10), "per_secs", r.integer(1, 3600));
            // quantized to 3 decimals so the limit is canonical-wire-safe
            case 3: return obj("k", "max_blast_radius", "max", new Json.Num(BigDecimal.valueOf(r.integer(0, 1000), 3).stripTrailingZeros().toPlainString()));
            case 4: return obj("k", "reversibility_max", "cls", r.pick("reversible", "rate_limited", "irreversible"));
            case 5: return obj("k", "delegation_depth", "max", r.integer(0, 20));
            default: return obj("k", "budget_frac", "frac", r.real(0, 1));
        }
    }

    private static List<Object> specs(Rng r, int min, int max) {
        List<Object> out = new ArrayList<>();
        for (long i = r.integer(min, max); i > 0; i--) out.add(caveatSpec(r));
        return out;
    }

    /** A chain model for {@link Invariants#buildChain}; the built chain is {caps, predicates, rootIssuer, holders}. */
    public static Map<String, Object> chainModel(Rng r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("principalSeed", seed32(r));
        m.put("holder0Seed", seed32(r));
        m.put("rootSpecs", specs(r, 1, 4));
        List<Object> hops = new ArrayList<>();
        for (long i = r.integer(0, 5); i > 0; i--) hops.add(obj("holderSeed", seed32(r), "addedSpecs", specs(r, 0, 3)));
        m.put("hops", hops);
        m.put("predicates", predicateList(r));
        return m;
    }

    public static Map<String, Object> chain(Rng r) { return Invariants.buildChain(chainModel(r)); }

    // ---- risk policy / inputs / budget -------------------------------------------------------------------------------------

    /** Non-negative risk weights {@code alpha..zeta} in [0, 2]. */
    public static Map<String, Object> riskWeights(Rng r) {
        return obj("alpha", r.real(0, 2), "beta", r.real(0, 2), "gamma", r.real(0, 2), "delta", r.real(0, 2), "epsilon", r.real(0, 2), "zeta", r.real(0, 2));
    }

    /** A well-formed risk policy (passes the core validation): kappa > 0, 0 <= theta1 <= theta2, the rest finite and >= 0. */
    public static Map<String, Object> riskPolicy(Rng r) {
        Map<String, Object> w = obj("alpha", r.real(0, 2), "beta", r.real(0, 2), "gamma", r.real(0, 2), "delta", r.real(0, 2), "epsilon", r.real(0, 2), "zeta", r.real(0, 2));
        double theta1 = r.real(0, 1), gap = r.real(0, 1);
        return obj("weights", w, "theta1", theta1, "theta2", theta1 + gap, "kappa", r.real(0.001, 5), "lambda", r.real(0, 0.01), "rho", r.real(0, 2), "bMax", r.real(0, 10));
    }

    public static Map<String, Object> riskInputs(Rng r) {
        return obj("semanticDistance", r.real(0, 1), "reversibility", r.real(0, 1), "blastRadius", r.real(0, 1), "taint", r.real(0, 1), "confidence", r.real(0, 1), "age", r.real(0, 1));
    }

    public static Map<String, Object> trustBudget(Rng r) {
        Map<String, Object> b = obj("B", r.real(0, 10), "tau", r.integer(0, 10_000_000));
        if (r.bool()) b.put("asOf", r.integer(0, 10_000_000));
        return b;
    }

    /** Non-negative deltas for a pointwise-worse risk input (the monotonicity property). */
    public static Map<String, Object> riskDeltas(Rng r) {
        return obj("dSem", r.real(0, 1), "dBlast", r.real(0, 1), "dTaint", r.real(0, 1), "dAge", r.real(0, 1), "dRev", r.real(0, 1), "dConf", r.real(0, 1));
    }
}
