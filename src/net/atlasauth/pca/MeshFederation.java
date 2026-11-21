package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Federation across mesh domains: an agent from one guardian acting on a resource governed by another. Three pure, fail-closed,
 * deterministic primitives over decoded JSON values:
 * <ol>
 * <li>{@link #translateCapability} / {@link #verifyTranslatedCapability}: a capability chain rooted in guardian A's grant is attenuated
 * into a capability valid in domain B. The bridge can ONLY NARROW: the translated caveat list is an append-only extension of the source
 * tip's, the bridge signs it, and the verifier also asserts the translated effective authority narrows the source's.</li>
 * <li>The federated budget ({@link #createFederatedBudget}, {@link #allocateSub}, {@link #spendFederated}): one trust-budget tree that
 * spans domains. An allocation is a ceiling guarded by the parent's remaining budget; a spend debits the spender and every ancestor,
 * atomically, so the whole delegation tree draws on ONE budget ({@link #federatedSafetyBound}).</li>
 * <li>The cross-reference ({@link #crossReferenceCommit}, {@link #anchorCrossReference}, {@link #verifyCrossReference}): both guardians
 * anchor the SAME commitment to a cross-domain action in their own logs, so neither can later claim a different action crossed.</li>
 * </ol>
 * The translator and the signers throw; the verifiers and the budget operations never do (a refusal is a result).
 */
public final class MeshFederation {
    private MeshFederation() {}

    static final String XCAP_DOMAIN = "atlas-pca/mesh-xcap/v1\0";
    static final String XANCHOR_DOMAIN = "atlas-pca/mesh-xanchor/v1\0";
    static final String ACTION_DIGEST_DOMAIN = "atlas-pca/mesh-action-digest/v1\0";
    static final int MAX_BUDGET_DEPTH = (int) Mesh.DEFAULT_MAX_CHAIN_LENGTH;
    private static final String MALFORMED = "malformed translated capability";

    private static Map<String, Object> rec(Object x) { return StoreJs.map(x); }
    private static boolean isNum(Object x) { return IntentJs.isFinite(x); }
    /** The value of a member {@link #isNum} has admitted. */
    private static double dbl(Object x) { return IntentJs.num(x); }

    // throws on a body strict canonical JSON refuses (negative zero, an unsafe integer, a lone surrogate ...)
    private static byte[] msg(String domain, Object body) { return Pca.concat(Json.utf8(domain), Pca.canonBytes(body)); }

    private static boolean isCaveatArray(Object x) {
        if (!(x instanceof List)) return false;
        for (Object c : (List<?>) x) if (!(c instanceof Map) || !(((Map<?, ?>) c).get("type") instanceof String)) return false;
        return true;
    }

    private static Map<String, Object> fail(String reason) { return Issue.obj("ok", false, "reason", reason); }

    // ---- 1. cross-domain capability translation ------------------------------------------------------------------------------

    private static Map<String, Object> xcapBody(Object from, Object to, Object sourceTip, Object caveats, Object issuedAt) {
        return Issue.obj("v", "atlas-pca/mesh-xcap/v1", "from", from, "to", to, "source_tip", sourceTip, "caveats", caveats, "issued_at", issuedAt);
    }

    /**
     * Translate a capability chain into the target domain. {@code args} is {@code {fromGuardian, toGuardian, issued_at, additionalCaveats?,
     * pqPins?}}: the new caveat list is the source tip's followed by {@code additionalCaveats} (append-only, so the bridge can only narrow),
     * and {@code pqPins} (issuer to pinned PQ key) is what admits a hybrid or post-quantum source root. {@code bridge} signs the result:
     * {@code {source, fromGuardian, toGuardian, bridge, source_tip, caveats, issued_at, sig}}. Throws on an invalid source chain, on
     * additional caveats that are not a list of objects with a string {@code type}, and on a value with no canonical form.
     */
    public static Map<String, Object> translateCapability(Object chain, Map<String, Object> args, Keys.EdKey bridge) {
        if (args == null || bridge == null) throw new IllegalArgumentException("translateCapability: arguments and the bridge key are required");
        List<Object> source = Pca.asList(chain); // anything but a list reads as an empty chain
        String why = Pca.verifyChain(source, null, false, null, rec(args.get("pqPins")), null);
        if (!why.isEmpty()) throw new IllegalArgumentException("translateCapability: invalid source chain: " + why);
        if (args.containsKey("additionalCaveats") && !isCaveatArray(args.get("additionalCaveats"))) {
            throw new IllegalArgumentException("translateCapability: additionalCaveats must be an array of caveats");
        }
        for (String k : new String[] {"fromGuardian", "toGuardian", "issued_at"}) {
            if (!args.containsKey(k)) throw new IllegalArgumentException("translateCapability: " + k + " is required");
        }
        Map<String, Object> tip = rec(source.get(source.size() - 1));
        // deep copies through the strict canonical form: anything unhashable is refused here
        List<Object> caveats = new ArrayList<>(Issue.norm(Pca.asList(tip.get("caveats"))));
        if (args.containsKey("additionalCaveats")) caveats.addAll(Issue.norm(Pca.asList(args.get("additionalCaveats"))));
        String sourceTip = Pca.capHash(tip);
        Object from = args.get("fromGuardian"), to = args.get("toGuardian"), issuedAt = args.get("issued_at");
        String sig = Keys.b64u(bridge.sign(msg(XCAP_DOMAIN, xcapBody(from, to, sourceTip, caveats, issuedAt))));
        return Issue.obj("source", chain, "fromGuardian", from, "toGuardian", to, "bridge", bridge.id(), "source_tip", sourceTip, "caveats", caveats,
            "issued_at", issuedAt, "sig", sig);
    }

    /**
     * The effective authority a translated capability grants in the target domain (the conjunction of its caveats, see
     * {@link Mesh#effectiveAuthority}); {@code {error}} when the value is not a translated capability or a caveat fails closed.
     */
    public static Map<String, Object> translatedEffectiveAuthority(Object tc) {
        Map<String, Object> m = rec(tc);
        if (m == null || !isCaveatArray(m.get("caveats"))) return Issue.obj("error", MALFORMED);
        return Mesh.authJson(Mesh.effective(m.get("caveats")));
    }

    /** {@link #verifyTranslatedCapability(Object, Object)} with no options. */
    public static Map<String, Object> verifyTranslatedCapability(Object tc) { return verifyTranslated(tc, new LinkedHashMap<>()); }

    /**
     * Verify a translated capability: its shape, the source chain (root pinned by {@code rootIssuer}, PQ roots by {@code pqPins}), the
     * {@code fromGuardian} / {@code toGuardian} / {@code bridge} pins, that it crosses a domain boundary, that it is bound to the source
     * tip, that its caveats extend the tip's without altering one, the bridge signature, that its effective authority narrows the
     * source's (an unknown caveat on either side fails closed) and, with {@code now}, that it has not expired. Returns
     * {@code {ok:true, from, to, bridge, effective}} or {@code {ok:false, reason}}; never throws. Options given as null are malformed,
     * as in the reference; a value that is not an object carries no options.
     */
    public static Map<String, Object> verifyTranslatedCapability(Object tc, Object opts) {
        if (opts == null) return fail(MALFORMED);
        return verifyTranslated(tc, opts instanceof Map ? rec(opts) : new LinkedHashMap<>());
    }

    private static Map<String, Object> verifyTranslated(Object raw, Map<String, Object> o) {
        try {
            Map<String, Object> tc = rec(raw);
            if (tc == null || !(tc.get("source") instanceof List)) return fail(MALFORMED);
            for (String k : new String[] {"fromGuardian", "toGuardian", "bridge", "source_tip", "sig"}) if (!(tc.get(k) instanceof String)) return fail(MALFORMED);
            if (!isNum(tc.get("issued_at")) || !isCaveatArray(tc.get("caveats"))) return fail(MALFORMED);
            String from = (String) tc.get("fromGuardian"), to = (String) tc.get("toGuardian"), bridge = (String) tc.get("bridge");

            // (1) the source chain; a pin that is not a string never equals the root's issuer
            List<Object> source = Pca.asList(tc.get("source"));
            Object pin = o.get("rootIssuer");
            String why = Pca.verifyChain(source, pin instanceof String ? (String) pin : null, o.containsKey("rootIssuer"), null, rec(o.get("pqPins")), null);
            if (!why.isEmpty()) return fail("source chain: " + why);

            // (2) guardian and bridge pins
            if (o.containsKey("fromGuardian") && !from.equals(o.get("fromGuardian"))) return fail("source guardian mismatch");
            if (o.containsKey("toGuardian") && !to.equals(o.get("toGuardian"))) return fail("target guardian mismatch");
            if (o.containsKey("bridge") && !bridge.equals(o.get("bridge"))) return fail("bridge key mismatch");
            if (from.equals(to)) return fail("translation does not cross a domain boundary");

            // (3) source tip binding
            Map<String, Object> tip = rec(source.get(source.size() - 1));
            if (!tc.get("source_tip").equals(Pca.capHash(tip))) return fail("source_tip does not match the source chain tip");

            // (4) append-only prefix over the source tip's caveats (the attenuation rule of a chain)
            List<Object> caveats = Pca.asList(tc.get("caveats")), tipCaveats = Pca.asList(tip.get("caveats"));
            if (caveats.size() < tipCaveats.size()) return fail("translation drops a source caveat (widening)");
            for (int j = 0; j < tipCaveats.size(); j++) {
                if (!Pca.hashCanonical(caveats.get(j)).equals(Pca.hashCanonical(tipCaveats.get(j)))) return fail("translation altered or reordered source caveat " + j + " (widening)");
            }

            // (5) bridge signature
            byte[] m = msg(XCAP_DOMAIN, xcapBody(from, to, tc.get("source_tip"), caveats, tc.get("issued_at")));
            if (!Pca.verifyB64u(bridge, m, (String) tc.get("sig"))) return fail("translation not signed by the declared bridge key");

            // (6) monotone narrowing of the effective authority (defence in depth)
            Mesh.Auth effS = Mesh.effective(tipCaveats);
            if (effS.err != null) return fail("source caveats: " + effS.err);
            Mesh.Auth effT = Mesh.effective(caveats);
            if (effT.err != null) return fail(effT.err);
            if (!Mesh.narrows(effT, effS)) return fail("translated authority widens the source authority");

            // (7) optional expiry
            if (o.containsKey("now") && effT.hasExp && !(Double.isFinite(jsNumber(o.get("now"))) && jsNumber(o.get("now")) <= effT.expiresAt)) return fail("translated capability expired");

            return Issue.obj("ok", true, "from", from, "to", to, "bridge", bridge, "effective", Mesh.authJson(effT));
        } catch (RuntimeException e) {
            return fail(MALFORMED);
        }
    }

    /** JavaScript ToNumber of a decoded JSON value, as the reference's {@code opts.now > expiresAt} reads a clock that is not a number. */
    static double jsNumber(Object v) { return Actions.jsNumber(v, true); }

    // ---- 2. the consolidated cross-domain budget ------------------------------------------------------------------------------

    private static double nz(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    private static Map<String, Object> budget(Object b) { return Issue.obj("B", b, "tau", StoreJs.num(0L)); }

    /** The node with its budget debited by {@code c} (never below zero). */
    private static Map<String, Object> debited(Map<String, Object> node, double c) {
        Map<String, Object> out = new LinkedHashMap<>(node);
        out.put("B", StoreJs.num(Math.max(0, dbl(node.get("B")) - nz(c))));
        return out;
    }

    private static Map<String, Object> okState(Map<String, Object> state) { return Issue.obj("ok", true, "state", state); }

    private static boolean validBudgetState(Object raw) {
        Map<String, Object> s = rec(raw);
        if (s == null || rec(s.get("nodes")) == null || !(s.get("root") instanceof String) || !isNum(s.get("kappa")) || !isNum(s.get("bMax"))) return false;
        if (dbl(s.get("kappa")) <= 0 || dbl(s.get("bMax")) < 0) return false;
        Map<String, Object> nodes = rec(s.get("nodes"));
        if (!nodes.containsKey((String) s.get("root"))) return false;
        for (Object v : nodes.values()) {
            Map<String, Object> n = rec(v);
            if (n == null || !(n.get("domain") instanceof String) || !isNum(n.get("B")) || dbl(n.get("B")) < 0) return false;
            if (n.containsKey("parent") && !(n.get("parent") instanceof String)) return false;
        }
        return true;
    }

    /**
     * Create the root of a federated budget from {@code {rootId, rootDomain, B0, kappa, bMax}}: {@code 0 <= B0 <= bMax} and
     * {@code kappa > 0}, all finite. Returns {@code {ok:true, state}} with {@code state = {nodes: {id: {domain, parent?, B}}, root,
     * kappa, bMax}} (an immutable value: every operation returns a new one), or {@code {ok:false, reason}}.
     */
    public static Map<String, Object> createFederatedBudget(Object args) {
        Map<String, Object> a = rec(args);
        if (a == null || !(a.get("rootId") instanceof String) || !(a.get("rootDomain") instanceof String)) return fail("malformed root");
        if (!isNum(a.get("kappa")) || dbl(a.get("kappa")) <= 0) return fail("kappa must be finite and > 0");
        if (!isNum(a.get("bMax")) || dbl(a.get("bMax")) < 0) return fail("bMax must be finite and >= 0");
        if (!isNum(a.get("B0")) || dbl(a.get("B0")) < 0) return fail("B0 must be finite and >= 0");
        if (dbl(a.get("B0")) > dbl(a.get("bMax"))) return fail("B0 exceeds bMax");
        Map<String, Object> nodes = Issue.obj((String) a.get("rootId"), Issue.obj("domain", a.get("rootDomain"), "B", a.get("B0")));
        return okState(Issue.obj("nodes", nodes, "root", a.get("rootId"), "kappa", a.get("kappa"), "bMax", a.get("bMax")));
    }

    /**
     * Allocate a sub-budget {@code {id, domain, parent, alloc}} under an existing node, possibly in another domain. The allocation is a
     * ceiling guarded against the parent's CURRENT remaining budget ({@code 0 <= alloc <= parent.B}); it does not reduce the parent:
     * consumption is charged when the sub-agent spends.
     */
    public static Map<String, Object> allocateSub(Object state, Object args) {
        if (!validBudgetState(state)) return fail("malformed budget state");
        Map<String, Object> s = rec(state), a = rec(args);
        if (a == null || !(a.get("id") instanceof String) || !(a.get("domain") instanceof String) || !(a.get("parent") instanceof String)) return fail("malformed allocation");
        Map<String, Object> nodes = rec(s.get("nodes"));
        if (nodes.containsKey((String) a.get("id"))) return fail("node id already exists");
        if (!nodes.containsKey((String) a.get("parent"))) return fail("unknown parent");
        Double alloc = IntentJs.num(a.get("alloc"));
        Map<String, Object> sub = RiskBudgets.subBudget(budget(rec(nodes.get((String) a.get("parent"))).get("B")), alloc == null ? Double.NaN : alloc);
        if (!Boolean.TRUE.equals(sub.get("ok"))) return fail((String) sub.get("reason"));
        Map<String, Object> next = new LinkedHashMap<>(nodes);
        next.put((String) a.get("id"), Issue.obj("domain", a.get("domain"), "parent", a.get("parent"), "B", rec(sub.get("sub")).get("B")));
        Map<String, Object> out = new LinkedHashMap<>(s);
        out.put("nodes", next);
        return okState(out);
    }

    /** The path from a node up to the root (node first), or the refusal: an unknown node, a cycle, a tree deeper than the bound, a stray subtree. */
    private static Object budgetPath(Map<String, Object> nodes, String root, String nodeId) {
        List<String> path = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        String cur = nodeId;
        while (cur != null) {
            if (!nodes.containsKey(cur)) return "unknown node";
            if (seen.contains(cur)) return "cycle in budget tree";
            if (path.size() >= MAX_BUDGET_DEPTH) return "budget tree too deep";
            seen.add(cur);
            path.add(cur);
            cur = (String) rec(nodes.get(cur)).get("parent"); // a valid state's parent is absent or a string
        }
        return path.get(path.size() - 1).equals(root) ? path : "node is not rooted at the budget root";
    }

    /**
     * A node spends {@code c}: the consolidated debit along the whole path to the root, across domain boundaries. Atomic: if the
     * spender or ANY ancestor cannot cover {@code c} nothing is debited and the first offender is named. So a swarm under any node,
     * in any mix of domains, can never collectively exceed that node's allocation.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> spendFederated(Object state, Object nodeId, Object c) {
        if (!validBudgetState(state)) return fail("malformed budget state");
        if (!(nodeId instanceof String)) return fail("malformed node id");
        if (!isNum(c) || dbl(c) < 0) return fail("spend must be finite and >= 0");
        Map<String, Object> s = rec(state), nodes = rec(s.get("nodes"));
        String rootId = (String) s.get("root"), id = (String) nodeId;
        double cost = dbl(c);
        Object p = budgetPath(nodes, rootId, id);
        if (p instanceof String) return fail((String) p);
        List<String> path = (List<String>) p;
        Map<String, Object> next = new LinkedHashMap<>(nodes);
        Map<String, Object> root = rec(nodes.get(rootId));
        if (id.equals(rootId)) {
            if (dbl(root.get("B")) < cost) return fail("root budget insufficient");
            next.put(rootId, debited(root, cost));
        } else {
            // the strict interior (everything between the spender and the root), then the root and the spender as one consolidated debit
            List<String> interior = path.subList(1, path.size() - 1);
            for (String a : interior) if (dbl(rec(nodes.get(a)).get("B")) < cost) return fail("ancestor \"" + a + "\" budget insufficient");
            Map<String, Object> node = rec(nodes.get(id));
            Map<String, Object> dc = RiskBudgets.debitConsolidated(budget(root.get("B")), budget(node.get("B")), cost);
            if (!Boolean.TRUE.equals(dc.get("ok"))) return fail((String) dc.get("reason"));
            next.put(id, debited(node, cost));
            next.put(rootId, debited(root, cost));
            for (String a : interior) next.put(a, debited(rec(nodes.get(a)), cost));
        }
        Map<String, Object> out = new LinkedHashMap<>(s);
        out.put("nodes", next);
        return okState(out);
    }

    /** The bound a federated budget enforces on the total risk of the whole delegation tree: {@code bMax / kappa} (0 for an unusable input). */
    public static double federatedSafetyBound(Object p) {
        Map<String, Object> m = rec(p);
        if (m == null || !isNum(m.get("bMax")) || !isNum(m.get("kappa"))) return 0;
        return dbl(m.get("kappa")) > 0 ? Math.max(0, dbl(m.get("bMax"))) / dbl(m.get("kappa")) : 0;
    }

    // ---- 3. mutual transparency: the cross-reference commitment ---------------------------------------------------------------

    /** The canonical digest of a mesh action (the value both guardians cross-reference). Throws on a value with no canonical form. */
    public static String meshActionDigest(Object action) { return Pca.hashCanonical(Issue.obj("v", ACTION_DIGEST_DOMAIN, "action", action)); }

    /**
     * The linking commitment both guardians anchor for {@code {action_digest, fromGuardian, toGuardian, nonce, at}}: it binds the action
     * and both domain identities, so the two logs commit the SAME value. Throws when a member is missing or has no canonical form.
     */
    public static String crossReferenceCommit(Object x) {
        Map<String, Object> m = rec(x);
        if (m == null) throw new IllegalArgumentException("crossReferenceCommit: not a cross-reference");
        for (String k : new String[] {"action_digest", "fromGuardian", "toGuardian", "nonce", "at"}) {
            if (!m.containsKey(k)) throw new IllegalArgumentException("crossReferenceCommit: " + k + " is missing");
        }
        return Pca.hashCanonical(Issue.obj("v", "atlas-pca/mesh-xref/v1", "action_digest", m.get("action_digest"), "from", m.get("fromGuardian"),
            "to", m.get("toGuardian"), "nonce", m.get("nonce"), "at", m.get("at")));
    }

    /**
     * A guardian anchors the commitment at position {@code seq} of its own log and signs {@code {commit, seq}}: {@code {domain, commit,
     * seq, sig}}. It signs whatever canonical value it is given; {@link #verifyCrossReference} is what requires a natural {@code seq}.
     */
    public static Map<String, Object> anchorCrossReference(Keys.EdKey domainKey, Object commit, Object seq) {
        String sig = Keys.b64u(domainKey.sign(msg(XANCHOR_DOMAIN, Issue.obj("commit", commit, "seq", seq))));
        return Issue.obj("domain", domainKey.id(), "commit", commit, "seq", seq, "sig", sig);
    }

    private static Map<String, Object> validAnchor(Object a) {
        Map<String, Object> m = rec(a);
        return m != null && m.get("domain") instanceof String && m.get("commit") instanceof String && IntentJs.isNonNeg(m.get("seq")) && m.get("sig") instanceof String ? m : null;
    }

    private static boolean anchorSigned(Map<String, Object> a) {
        return Pca.verifyB64u((String) a.get("domain"), msg(XANCHOR_DOMAIN, Issue.obj("commit", a.get("commit"), "seq", a.get("seq"))), (String) a.get("sig"));
    }

    /**
     * Verify mutual transparency for a cross-domain action against {@code {from, to}} anchors: BOTH guardians anchored the SAME
     * commitment, each under its own key, for two distinct domains. Returns {@code {ok:true, commit}} or {@code {ok:false, reason}};
     * never throws.
     */
    public static Map<String, Object> verifyCrossReference(Object x, Object anchors) {
        try {
            Map<String, Object> m = rec(x);
            if (m == null || !isNum(m.get("at"))) return fail("malformed cross-reference");
            for (String k : new String[] {"action_digest", "fromGuardian", "toGuardian", "nonce"}) if (!(m.get(k) instanceof String)) return fail("malformed cross-reference");
            Map<String, Object> an = rec(anchors);
            Map<String, Object> from = an == null ? null : validAnchor(an.get("from")), to = an == null ? null : validAnchor(an.get("to"));
            if (from == null || to == null) return fail("malformed anchors");
            if (m.get("fromGuardian").equals(m.get("toGuardian"))) return fail("cross-reference must span two distinct domains");
            String expected = crossReferenceCommit(m);
            if (!from.get("domain").equals(m.get("fromGuardian"))) return fail("source anchor domain does not match the cross-reference");
            if (!to.get("domain").equals(m.get("toGuardian"))) return fail("target anchor domain does not match the cross-reference");
            if (!from.get("commit").equals(expected)) return fail("source anchor commits a different action");
            if (!to.get("commit").equals(expected)) return fail("target anchor commits a different action");
            if (!anchorSigned(from)) return fail("source anchor signature invalid");
            if (!anchorSigned(to)) return fail("target anchor signature invalid");
            return Issue.obj("ok", true, "commit", expected);
        } catch (RuntimeException e) {
            return fail("malformed cross-reference");
        }
    }
}
