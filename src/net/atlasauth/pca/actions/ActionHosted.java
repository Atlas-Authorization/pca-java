package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import net.atlasauth.pca.ActionRegistry;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Pca;

/**
 * The hosted action registry of one instance: the publish gate (what a new version of a namespace may change without a reviewer) and the verifier's view of the
 * active versions (provenance facts, trait floors for rule 22, undo eligibility, the server reversibility class, compiled business rules). Pure: storage, keys
 * and time are the caller's. Fail closed everywhere: an action the view does not know, one that is not confirmed by a reviewer key the instance pins, or a
 * deprecated one gets the top of the trait registry (every floor) and no provenance facts, is irreversible, and is never undoable. Everything is a JSON tree.
 */
public final class ActionHosted {
    private ActionHosted() {}

    public static final String RULES_DOC_KIND = "pca-action-rules";
    public static final String HOSTED_VERSION_DOMAIN = "atlas-pca/hosted-action-version/v1";
    private static final Pattern PLAIN_SEMVER = Pattern.compile("[0-9]+\\.[0-9]+\\.[0-9]+");
    private static final List<String> EFFECTIVE_DIMS = List.of("confirmation", "effective.traits", "effective.profile");
    private static final List<String> CAVEAT_KINDS = List.of("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap");
    private static final Map<String, String> SERVER_CLASS = Map.of("reversible", "reversible", "rate_limited", "costly", "irreversible", "irreversible");

    private static boolean has(Object m, String k) { return m instanceof Map && ((Map<?, ?>) m).containsKey(k); }
    private static boolean plainObject(Object x) { return x instanceof Map; }

    private static boolean truthy(Object v) {
        if (v == null || Boolean.FALSE.equals(v) || "".equals(v)) return false;
        Double d = J.num(v);
        return d == null || !(d == 0 || d.isNaN());
    }

    private static Map<String, Object> fail(String code, String reason, List<String> verbs) {
        Map<String, Object> m = J.obj("ok", Boolean.FALSE, "code", code, "reason", reason);
        if (verbs != null) m.put("verbs", J.objs(verbs));
        return m;
    }

    /** The trait registry of a version: core plus its custom traits. Throws for custom traits that do not extend their implies. */
    public static Actions.Registry registryOfTraits(List<?> traits) { return traits.isEmpty() ? Actions.CORE_REGISTRY : Actions.extendRegistry(Actions.CORE_REGISTRY, new ArrayList<Object>(traits)); }

    /** The attestation check the instance pins give (null without pins: nothing is confirmed). */
    public static Predicate<Map<String, Object>> reviewOptsOf(Object pins, Actions.Registry reg) { return pins == null ? null : ActionUndoEngine.attestationVerifier(pins, reg); }

    /** Null iff {@code x} is a rules document for {@code ns} whose every verb is in {@code defs} and whose rules lint without errors. */
    public static String rulesDocError(Object x, String ns, List<?> defs) {
        if (!plainObject(x)) return "rules must be a pca-action-rules document";
        Map<String, Object> r = J.m(x);
        for (String k : r.keySet()) if (!List.of("v", "kind", "ns", "rules", "reviews").contains(k)) return "rules: unknown member '" + k + "'";
        Double v = J.num(r.get("v"));
        if (v == null || v != 1.0 || !RULES_DOC_KIND.equals(r.get("kind"))) return "rules: not a " + RULES_DOC_KIND + " v1 document";
        if (!ns.equals(r.get("ns"))) return "rules: ns '" + (r.containsKey("ns") ? J.jsStr(r.get("ns")) : "undefined") + "' is not the pack's '" + ns + "'";
        if (!plainObject(r.get("rules"))) return "rules.rules must map verbs to rules blocks";
        if (r.containsKey("reviews") && !plainObject(r.get("reviews"))) return "rules.reviews must map verbs to rules reviews";
        Map<String, Map<String, Object>> byVerb = new LinkedHashMap<>();
        for (Object d : defs) byVerb.put((String) J.get(d, "verb"), J.m(d));
        for (Map.Entry<String, Object> e : J.m(r.get("rules")).entrySet()) {
            Map<String, Object> d = byVerb.get(e.getKey());
            if (d == null) return "rules: '" + e.getKey() + "' is not an action of the pack";
            List<String> errs = new ArrayList<>();
            for (Object f : ActionBusinessRules.lintBusinessRules(d, e.getValue())) if ("error".equals(J.get(f, "severity"))) errs.add((String) J.get(f, "message"));
            if (!errs.isEmpty()) return "rules for '" + e.getKey() + "': " + String.join("; ", errs);
        }
        if (r.containsKey("reviews")) for (String verb : J.m(r.get("reviews")).keySet()) if (!byVerb.containsKey(verb)) return "rules.reviews: '" + verb + "' is not an action of the pack";
        return null;
    }

    /** The content address of a version: the digest of {@code {pack, rules, traits, deprecated}}. */
    public static String hostedVersionDigest(Map<String, Object> v) {
        List<String> dep = new ArrayList<>();
        for (Object x : J.a(v.get("deprecated"))) dep.add((String) x);
        dep.sort(null);
        return Pca.hashCanonical(J.obj("d", HOSTED_VERSION_DOMAIN, "pack", v.get("pack"), "rules", v.get("rules"), "traits", v.get("traits"), "deprecated", J.objs(dep)));
    }

    private static boolean safeConfirmed(Map<String, Object> d, Predicate<Map<String, Object>> review) {
        try { return ActionEffective.isConfirmed(d, review); } catch (RuntimeException e) { return false; }
    }

    /** diffDefs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions). */
    private static Map<String, Object> diffDefsAcross(Map<String, Object> o, Map<String, Object> n, Actions.Registry oReg, Actions.Registry nReg, Predicate<Map<String, Object>> oRev, Predicate<Map<String, Object>> nRev) {
        Map<String, Object> base = ActionDiff.diffDefs(o, n, nReg, nRev);
        if (oReg == nReg) return base;
        Map<String, Object> eo = J.m(ActionEffective.effective(o, oReg, oRev).get("eff")), en = J.m(ActionEffective.effective(n, nReg, nRev).get("eff"));
        String rel = ActionEffective.leq(eo, en) ? (ActionEffective.leq(en, eo) ? null : "narrow") : ActionEffective.leq(en, eo) ? "widen" : "incomparable";
        if (rel == null) return base;
        List<String> reasons = new ArrayList<>();
        for (Object r : J.a(base.get("reasons"))) if (!((String) r).startsWith("effective.profile")) reasons.add((String) r);
        reasons.add("effective.profile: " + rel);
        reasons.sort(null);
        Object bc = base.get("class");
        boolean inc = rel.equals("incomparable") || "incomparable".equals(bc) || (rel.equals("widen") && "narrow".equals(bc)) || (rel.equals("narrow") && "widen".equals(bc));
        String cls = inc ? "incomparable" : rel.equals("widen") || "widen".equals(bc) ? "widen" : "narrow";
        return J.obj("class", cls, "reasons", J.objs(reasons));
    }

    private static int byVerbKey(Object a, Object b) { return ((String) J.get(a, "verb")).compareTo((String) J.get(b, "verb")); }

    /**
     * Decide whether a version may become the active one of its namespace, and compute what it changes. {@code i}: {@code {current?, pack, rules?, traits?,
     * publisherKeys, pins?, pin?}}. Returns {@code {ok:true, version}} or {@code {ok:false, code, reason, verbs?, changes?}} where code is one of
     * bad_pack, bad_rules, bad_traits, bad_version, ns_mismatch, not_newer, widen_unreviewed.
     */
    public static Map<String, Object> publishGate(Map<String, Object> i) {
        List<Object> traits = new ArrayList<>();
        if (i.containsKey("traits")) {
            if (!(i.get("traits") instanceof List)) return fail("bad_traits", "traits must be a list of trait definitions", null);
            traits = J.a(i.get("traits"));
        }
        Actions.Registry reg;
        try { reg = registryOfTraits(traits); } catch (RuntimeException e) { return fail("bad_traits", e.getMessage(), null); }
        Map<String, Object> pv = ActionBuild.verifyPack(i.get("pack"), i.get("publisherKeys"), reg);
        if (!Boolean.TRUE.equals(pv.get("ok"))) return fail("bad_pack", (String) pv.get("reason"), null);
        Map<String, Object> pack = J.m(i.get("pack"));
        String packVersion = (String) pack.get("version"), packNs = (String) pack.get("ns");
        if (!PLAIN_SEMVER.matcher(packVersion).matches()) return fail("bad_version", "version '" + packVersion + "' must be MAJOR.MINOR.PATCH", null);
        Map<String, Object> cur = i.get("current") instanceof Map ? J.m(i.get("current")) : null;
        if (cur != null && !packNs.equals(cur.get("ns"))) return fail("ns_mismatch", "the active namespace is '" + cur.get("ns") + "', the pack is '" + packNs + "'", null);
        if (cur != null && !truthy(i.get("pin")) && ActionRegistry.compareVersions(packVersion, (String) cur.get("version")) <= 0) return fail("not_newer", "version " + packVersion + " is not above the active " + cur.get("version"), null);
        Object rulesIn = i.containsKey("rules") ? i.get("rules") : J.obj("v", J.n(1), "kind", RULES_DOC_KIND, "ns", packNs, "rules", new LinkedHashMap<String, Object>());
        List<Object> packDefs = J.a(pack.get("defs"));
        String re = rulesDocError(rulesIn, packNs, packDefs);
        if (re != null) return fail("bad_rules", re, null);
        Map<String, Object> rules = J.m(rulesIn);
        Map<String, Object> ruleBlocks = J.m(rules.get("rules"));

        Predicate<Map<String, Object>> review = reviewOptsOf(i.get("pins"), reg);
        Actions.Registry prevReg = reg;
        if (cur != null) { try { prevReg = registryOfTraits(J.a(cur.get("traits"))); } catch (RuntimeException e) { prevReg = reg; } }
        Predicate<Map<String, Object>> prevReview = reviewOptsOf(i.get("pins"), prevReg);
        List<Object> changes = new ArrayList<>();
        List<String> blocked = new ArrayList<>(), reasons = new ArrayList<>();
        Map<String, Map<String, Object>> oldDefs = new LinkedHashMap<>();
        if (cur != null) for (Object d : J.a(J.get(cur.get("pack"), "defs"))) oldDefs.put((String) J.get(d, "verb"), J.m(d));
        Set<Object> oldDep = new HashSet<>(cur != null ? J.a(cur.get("deprecated")) : List.of());
        Set<Object> newVerbs = new HashSet<>();
        for (Object d : packDefs) newVerbs.add(J.get(d, "verb"));
        for (Object n0 : packDefs) {
            Map<String, Object> n = J.m(n0);
            String verb = (String) n.get("verb");
            Map<String, Object> o = oldDefs.get(verb);
            boolean hasNewRules = ruleBlocks.containsKey(verb);
            Object newRules = ruleBlocks.get(verb);
            boolean confirmed = safeConfirmed(n, review);
            Map<String, Object> change;
            if (o == null || oldDep.contains(verb)) {
                change = J.obj("verb", verb, "class", "added", "reasons", new ArrayList<Object>());
                if (confirmed) change.put("reviewed", Boolean.TRUE);
            } else {
                Map<String, Object> d = diffDefsAcross(o, n, prevReg, reg, prevReview, review);
                change = J.obj("verb", verb, "class", d.get("class"), "reasons", d.get("reasons"));
                boolean effWidens = false;
                for (Object r : J.a(d.get("reasons"))) for (String dim : EFFECTIVE_DIMS) if (((String) r).startsWith(dim + ": widen") || ((String) r).startsWith(dim + ": incomparable")) effWidens = true;
                if (effWidens) {
                    if (confirmed) change.put("reviewed", Boolean.TRUE);
                    else { blocked.add(verb); reasons.add(verb + ": its effective authority widens without a valid confirmation of the new definition"); }
                }
            }
            Object oldRules = o != null && !oldDep.contains(verb) ? J.get(J.get(cur.get("rules"), "rules"), verb) : null;
            if (oldRules != null || hasNewRules) {
                Map<String, Object> rd;
                try { rd = ActionBusinessRules.diffBusinessRules(n, oldRules == null ? null : J.m(oldRules), newRules == null ? null : J.m(newRules)); }
                catch (RuntimeException e) { rd = J.obj("class", "incomparable", "reasons", J.list("rules: " + e.getMessage())); }
                // rules apply to confirmed and unconfirmed actions alike, so any widening of them needs a reviewer, whatever the state of the definition
                if (!"equal".equals(rd.get("class"))) change.put("rules", rd);
                if ("widen".equals(rd.get("class")) || "incomparable".equals(rd.get("class"))) {
                    // removing every rule is reviewed as the empty block
                    String err = ActionBusinessRules.rulesReviewError(J.get(rules.get("reviews"), verb), n, newRules == null ? new LinkedHashMap<>() : J.m(newRules), i.get("pins"));
                    if (err == null) change.put("reviewed", Boolean.TRUE);
                    else {
                        blocked.add(verb);
                        List<String> rr = new ArrayList<>();
                        for (Object x : J.a(rd.get("reasons"))) rr.add((String) x);
                        reasons.add(verb + ": its business rules widen (" + String.join(", ", rr) + ") without a valid rules review: " + err);
                    }
                }
            }
            if (!"equal".equals(change.get("class")) || change.containsKey("rules")) changes.add(change);
        }
        TreeSet<String> deprecated = new TreeSet<>();
        for (Object v : oldDep) if (!newVerbs.contains(v)) deprecated.add((String) v);
        for (String v : oldDefs.keySet()) {
            if (newVerbs.contains(v) || oldDep.contains(v)) continue;
            deprecated.add(v);
            changes.add(J.obj("verb", v, "class", "deprecated", "reasons", J.list("removed from the namespace: treated as unknown")));
        }
        changes.sort(ActionHosted::byVerbKey);
        if (!blocked.isEmpty()) {
            Map<String, Object> out = fail("widen_unreviewed", String.join("\n", reasons), new ArrayList<>(new TreeSet<>(blocked)));
            out.put("changes", changes);
            return out;
        }
        List<Object> depList = J.objs(new ArrayList<>(deprecated));
        Map<String, Object> body = J.obj("pack", pack, "rules", rules, "traits", traits, "deprecated", depList);
        Map<String, Object> version = J.obj("ns", packNs, "version", packVersion, "digest", hostedVersionDigest(body), "prev", cur != null && cur.get("digest") != null ? cur.get("digest") : null);
        version.putAll(body);
        version.put("changes", changes);
        return J.obj("ok", Boolean.TRUE, "version", version);
    }

    // ---- the verifier's view --------------------------------------------------------------------------------------------------

    /** A rules block that no longer compiles denies every call of its action (its tightening must not silently disappear). */
    private static Map<String, Object> brokenRules(String verb) {
        return J.obj("v", J.n(1), "verb", verb, "rules_digest", "", "def_digest", "",
            "tighten", J.list(J.obj("id", "rules_broken", "when", J.obj("field", "action.verb", "op", "eq", "value", verb), "signal", "deny", "reason", "the business rules of this action no longer compile")), "accumulators", new ArrayList<Object>());
    }

    private static final class Entry {
        final Map<String, Object> def, rules;
        final Actions.Registry reg;
        final Predicate<Map<String, Object>> review;
        Entry(Map<String, Object> def, Actions.Registry reg, Predicate<Map<String, Object>> review, Map<String, Object> rules) { this.def = def; this.reg = reg; this.review = review; this.rules = rules; }
    }

    /** The verifier's view of the active versions of an instance. */
    public static final class View {
        public final List<String> versions = new ArrayList<>();
        private final Map<String, Entry> byVerb = new LinkedHashMap<>();
        private final Set<String> deprecated = new HashSet<>(), broken = new LinkedHashSet<>();
        private final Map<String, Map<String, Object>> prov = new HashMap<>(), cache = new HashMap<>();
        private final Map<Actions.Registry, ActionUndoEngine> undoByReg = new IdentityHashMap<>();
        private final Map<String, Object> top;
        private final List<Object> topTraitIds;

        View(List<?> vs, Object pins) {
            List<Actions.Registry> regs = new ArrayList<>();
            for (Object v : vs) {
                versions.add(J.get(v, "ns") + "@" + J.get(v, "version"));
                Actions.Registry reg;
                try { reg = registryOfTraits(J.a(J.get(v, "traits"))); } catch (RuntimeException e) {
                    Object defs = J.get(J.get(v, "pack"), "defs");
                    if (defs instanceof List) for (Object d : (List<?>) defs) if (J.get(d, "verb") instanceof String) broken.add((String) J.get(d, "verb"));
                    continue;
                }
                regs.add(reg);
                Predicate<Map<String, Object>> review = reviewOptsOf(pins, reg);
                Object blocks = J.get(J.get(v, "rules"), "rules");
                for (Object d : J.a(J.get(J.get(v, "pack"), "defs"))) {
                    String verb = (String) J.get(d, "verb");
                    if (byVerb.containsKey(verb)) continue;
                    Object rb = blocks instanceof Map ? J.m(blocks).get(verb) : null;
                    byVerb.put(verb, new Entry(J.m(d), reg, review, rb instanceof Map ? J.m(rb) : null));
                }
                for (Object x : J.a(J.get(v, "deprecated"))) deprecated.add((String) x);
            }
            for (String x : deprecated) byVerb.remove(x);
            for (String x : broken) byVerb.remove(x);
            // the strictest profile any active registry has (an unknown verb could be anything)
            Map<String, Object> t = null;
            List<Actions.Registry> used = regs.isEmpty() ? List.of(Actions.CORE_REGISTRY) : regs;
            for (Actions.Registry r : used) {
                Map<String, Object> p = Actions.floorOf(r, Actions.topTraits(r)).toMap();
                t = t == null ? p : ActionEffective.leq(t, p) ? p : ActionEffective.leq(p, t) ? t : ActionEffective.join(t, p);
            }
            top = t;
            TreeSet<String> ids = new TreeSet<>();
            for (Actions.Registry r : used) ids.addAll(Actions.topTraits(r));
            topTraitIds = new ArrayList<Object>(ids);
            for (Map.Entry<String, Entry> e : byVerb.entrySet()) {
                try { if (safeConfirmed(e.getValue().def, e.getValue().review)) prov.put(e.getKey(), ActionProvenance.provenanceInfoOf(e.getValue().def, e.getValue().reg, e.getValue().review)); } catch (RuntimeException ex) { /* unknown: sensitive */ }
            }
            Map<Actions.Registry, List<Object>> groups = new IdentityHashMap<>();
            List<Actions.Registry> order = new ArrayList<>();
            for (Entry e : byVerb.values()) {
                if (!groups.containsKey(e.reg)) { groups.put(e.reg, new ArrayList<>()); order.add(e.reg); }
                groups.get(e.reg).add(e.def);
            }
            for (Actions.Registry r : order) undoByReg.put(r, ActionUndoEngine.undoEngine(groups.get(r), pins, r));
        }

        /** What the view knows of a verb: {@code {verb, confirmed, known, deprecated, def_digest?, idempotency_param?, profile, traits, serverClass, rules?}}. */
        public Map<String, Object> lookup(String verb) {
            Map<String, Object> hit = cache.get(verb);
            if (hit != null) return hit;
            Entry e = byVerb.get(verb);
            Map<String, Object> out = J.obj("verb", verb, "confirmed", Boolean.FALSE, "known", e != null, "deprecated", deprecated.contains(verb), "profile", top, "traits", topTraitIds, "serverClass", "irreversible");
            if (e == null && broken.contains(verb) && !deprecated.contains(verb)) { out.put("known", Boolean.TRUE); out.put("rules", brokenRules(verb)); }
            if (e != null) {
                try {
                    Map<String, Object> eff = ActionEffective.effective(e.def, e.reg, e.review);
                    boolean confirmed = Boolean.TRUE.equals(eff.get("confirmed"));
                    Object idem = e.def.get("idempotency");
                    Object idemParam = idem != null && "key_param".equals(J.get(idem, "mode")) ? J.get(idem, "param") : null;
                    String digest = Actions.defDigest(e.def);
                    String serverClass = confirmed ? SERVER_CLASS.get(J.get(eff.get("eff"), "rev")) : null;
                    out.put("def_digest", digest);
                    if (idemParam != null) out.put("idempotency_param", idemParam);
                    out.put("confirmed", confirmed);
                    if (confirmed) { out.put("profile", eff.get("eff")); out.put("traits", eff.get("traits")); out.put("serverClass", serverClass); }
                    // rules apply whether or not the action is confirmed: they only tighten
                    if (e.rules != null) out.put("rules", ActionBusinessRules.compileBusinessRules(e.def, e.rules));
                } catch (RuntimeException ex) {
                    // a def or rules block that no longer compiles: unknown-strict, and its rules cannot be dropped silently
                    out.put("confirmed", Boolean.FALSE);
                    out.put("profile", top);
                    out.put("traits", topTraitIds);
                    out.put("serverClass", "irreversible");
                    out.put("rules", brokenRules(verb));
                }
            }
            cache.put(verb, out);
            return out;
        }

        /** The provenance facts of a confirmed, non-deprecated exact verb; null otherwise (sensitive). */
        public Map<String, Object> provenance(String verb) { return prov.get(verb); }

        /** Undo eligibility from confirmed definitions (exact verb; a deprecated action never): the plan or null. */
        public Map<String, Object> undoPlan(Map<String, Object> op) {
            Entry e = byVerb.get((String) op.get("verb"));
            return e == null ? null : undoByReg.get(e.reg).plan(op);
        }

        /** Rule 22: the floor decision for this action under what the grant provides ({@code {caveats, max_esc, preauth_esc}}) and the call context the server observed. */
        public String floor(String verb, Map<String, Object> grant, List<?> callContext) {
            try {
                List<Object> kinds = new ArrayList<>();
                for (Object c : J.a(grant.get("caveats"))) if (CAVEAT_KINDS.contains(c)) kinds.add(c);
                Object maxEsc = grant.get("max_esc"), pre = grant.get("preauth_esc");
                if (!nonNeg(maxEsc) || !nonNeg(pre)) return "deny";
                Map<String, Object> rho = J.m(lookup(verb).get("profile"));
                double esc = J.num(rho.get("esc"));
                if (esc > J.num(maxEsc)) return "deny";
                if (!kinds.containsAll(J.a(rho.get("caveats"))) || !callContext.containsAll(J.a(rho.get("context"))) || esc > J.num(pre)) return "escalate";
                return "allow";
            } catch (RuntimeException e) {
                return "deny";
            }
        }

        private static boolean nonNeg(Object v) { return J.isInt(v) && J.num(v) >= 0; }
    }

    /** Build the verifier's view from the active versions of an instance ({@code pins} may be null). */
    public static View hostedView(List<?> versions, Object pins) { return new View(versions, pins); }

    /** Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers. */
    public static Map<String, Object> grantFactsOf(Object grant) {
        Map<String, Object> env = Authorize.readEnvelope(grant);
        Object a = env == null ? null : env.get("actions");
        List<Object> caveats = new ArrayList<>();
        if (env != null && env.get("caveats") instanceof List) for (Object c : (List<?>) env.get("caveats")) { Object t = J.get(c, "type"); if (t instanceof String) caveats.add(t); }
        if (J.get(a, "caveats") instanceof List) for (Object t : (List<?>) J.get(a, "caveats")) if (t instanceof String) caveats.add(t);
        return J.obj("caveats", caveats, "max_esc", J.n(tier(J.get(a, "max_esc"), 3)), "preauth_esc", J.n(tier(J.get(a, "preauth_esc"), 0)));
    }

    private static long tier(Object v, long d) { return J.isInt(v) && J.num(v) >= 0 && J.num(v) <= 3 ? J.num(v).longValue() : d; }

    /** The context keys the hosted server itself establishes for a call: it always checks revocation fresh; an idempotency key present. */
    public static List<Object> hostedCallContext(Map<String, Object> lookup, Map<String, Object> params) {
        List<Object> out = J.list("fresh_revocation");
        Object k = lookup == null ? null : lookup.get("idempotency_param");
        if (k instanceof String && params != null && params.get(k) instanceof String && !((String) params.get(k)).isEmpty()) out.add("idempotency");
        return out;
    }

    /**
     * The event keys of a rules block's rate limits: {@code [{id, ms, key?}]}. A key names the verb, the window and the scope id (never a rule index or the
     * rules digest), so editing or reordering the rules never resets a count. {@code who}: {@code {principal?, org?}}.
     */
    public static List<Object> rateKeysOf(Map<String, Object> c, Map<String, Object> who) {
        List<Object> out = new ArrayList<>();
        for (Object a : J.a(c.get("accumulators"))) {
            String scope = "org".equals(J.get(a, "scope")) ? "org" : "principal";
            Object id = who.get(scope.equals("org") ? "org" : "principal");
            Object win = J.get(a, "win");
            Json0 ms = new Json0("task".equals(J.get(win, "kind")) ? 0.0 : J.num(J.get(win, "ms")));
            Map<String, Object> r = J.obj("id", J.get(a, "id"), "ms", ms.num());
            if (id instanceof String && !((String) id).isEmpty() && ms.v > 0) r.put("key", J.get(c, "verb") + "|" + J.jsStr(ms.num()) + "|" + scope + ":" + id);
            out.add(r);
        }
        return out;
    }

    private static final class Json0 {
        final double v;
        Json0(double v) { this.v = v; }
        net.atlasauth.pca.Json.Num num() { return new net.atlasauth.pca.Json.Num(net.atlasauth.pca.AttestCommon.jsNumString(v)); }
    }
}
