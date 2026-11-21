package net.atlasauth.pca.policyci;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Authorize;

/**
 * Input detection and normalization. {@code lintPolicy} accepts a bare predicate/caveat set, a compiled policy, a signed envelope or
 * a minted grant; they all reduce to one effective authority: {@code {predicates, caveats, riskPolicy?, kind}}.
 */
public final class Normalize {
    private Normalize() {}

    /** The caveat type that carries the signed envelope payload inside a grant. */
    static final String ENVELOPE_CAVEAT_TYPE = "envelope";

    /** A minted grant / delegation hop: has the content-addressed, signed shape of a capability. */
    public static boolean isCapability(Object x) {
        if (!Js.isRecord(x)) return false;
        return Js.get(x, "id") instanceof String && Js.get(x, "issuer") instanceof String && Js.get(x, "holder") instanceof String
            && Js.get(x, "body_digest") instanceof String && Js.get(x, "sig") instanceof String && Js.get(x, "caveats") instanceof List;
    }

    /** A signed policy envelope (the root intent grant payload). */
    public static boolean isEnvelope(Object x) {
        if (!Js.isRecord(x)) return false;
        return Js.get(x, "goal_commit") instanceof String && Js.get(x, "predicates") instanceof List && Js.get(x, "caveats") instanceof List
            && Js.isRecord(Js.get(x, "agent_binding")) && Js.isRecord(Js.get(x, "risk_policy"));
    }

    private static boolean isCompiledPolicy(Object x) {
        return Js.isRecord(x) && Js.get(x, "predicates") instanceof List && Js.get(x, "caveats") instanceof List && Js.isRecord(Js.get(x, "riskPolicy")) && Js.get(x, "actions") instanceof List;
    }

    private static boolean isBarePolicy(Object x) { return Js.isRecord(x) && Js.get(x, "predicates") instanceof List; }

    /** Drop the envelope-carrying caveat; keep the runtime gate caveats (and any appended attenuation). */
    private static List<Object> runtimeCaveats(List<?> caveats) {
        List<Object> out = new ArrayList<>();
        for (Object c : caveats) if (Js.isObject(c) && !ENVELOPE_CAVEAT_TYPE.equals(Js.get(c, "type"))) out.add(c);
        return out;
    }

    private static Map<String, Object> ok(Map<String, Object> policy) { return Js.obj("ok", true, "policy", policy); }
    private static Map<String, Object> fail(String reason) { return Js.obj("ok", false, "reason", reason); }

    private static Map<String, Object> policy(Object predicates, Object caveats, Object riskPolicy, boolean hasRisk, String kind) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("predicates", predicates);
        p.put("caveats", caveats);
        if (hasRisk) p.put("riskPolicy", riskPolicy);
        p.put("kind", kind);
        return p;
    }

    /**
     * Reduce a grant to its effective authority: its predicates and baseline gate caveats live inside its first envelope caveat, and
     * delegation appends further gate caveats to the grant's own caveats, so the effective gates are both lists together.
     */
    public static Map<String, Object> fromGrant(Object grant) {
        Map<String, Object> env = Authorize.readEnvelope(grant);
        if (env == null) return fail("grant has no readable `envelope` caveat (malformed or unsigned payload)");
        Object gc = Js.get(grant, "caveats");
        List<Object> caveats = new ArrayList<>((List<?>) env.get("caveats"));
        caveats.addAll(runtimeCaveats(gc instanceof List ? (List<?>) gc : List.of()));
        return ok(policy(env.get("predicates"), caveats, env.get("risk_policy"), true, "grant"));
    }

    /** Normalize any single-policy input to its effective authority: {@code {ok:true, policy}} or {@code {ok:false, reason}}. */
    public static Map<String, Object> normalizePolicyInput(Object input) {
        if (isCapability(input)) return fromGrant(input);
        if (isEnvelope(input)) return ok(policy(Js.get(input, "predicates"), Js.get(input, "caveats"), Js.get(input, "risk_policy"), true, "envelope"));
        if (isCompiledPolicy(input)) return ok(policy(Js.get(input, "predicates"), Js.get(input, "caveats"), Js.get(input, "riskPolicy"), true, "compiled"));
        if (isBarePolicy(input)) {
            Object c = Js.get(input, "caveats");
            return ok(policy(Js.get(input, "predicates"), c instanceof List ? c : new ArrayList<Object>(), null, false, "bare"));
        }
        return fail("unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })");
    }

    /**
     * Normalize a delegation chain (root to leaf) to one effective policy per hop: {@code {ok:true, hops}} or {@code {ok:false, reason}}. A
     * chain of grants shares the root envelope's predicates and each hop's gates are the envelope's caveats plus that hop's appended
     * ones; a chain of already-effective policies is taken as it is.
     */
    public static Map<String, Object> normalizeChain(List<?> chain) {
        if (chain.isEmpty()) return fail("empty chain");
        boolean allCaps = true;
        for (Object c : chain) if (!isCapability(c)) { allCaps = false; break; }
        if (allCaps) {
            Map<String, Object> env = Authorize.readEnvelope(chain.get(0));
            if (env == null) return fail("root grant has no readable `envelope` caveat");
            List<Object> hops = new ArrayList<>();
            for (Object cap : chain) {
                Object cc = Js.get(cap, "caveats");
                List<Object> caveats = new ArrayList<>((List<?>) env.get("caveats"));
                caveats.addAll(runtimeCaveats(cc instanceof List ? (List<?>) cc : List.of()));
                hops.add(policy(env.get("predicates"), caveats, env.get("risk_policy"), true, "chain-hop"));
            }
            return Js.obj("ok", true, "hops", hops);
        }
        List<Object> hops = new ArrayList<>();
        for (int i = 0; i < chain.size(); i++) {
            Map<String, Object> r = normalizePolicyInput(chain.get(i));
            if (!Boolean.TRUE.equals(r.get("ok"))) return fail("hop " + i + ": " + r.get("reason"));
            @SuppressWarnings("unchecked") Map<String, Object> p = new LinkedHashMap<>((Map<String, Object>) r.get("policy"));
            p.put("kind", "chain-hop");
            hops.add(p);
        }
        return Js.obj("ok", true, "hops", hops);
    }
}
