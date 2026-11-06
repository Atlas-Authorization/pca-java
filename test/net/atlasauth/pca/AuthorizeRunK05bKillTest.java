package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Authorize.run, the pipeline after the core checks: the stock caveat context (now, depth, blast radius, class, recent
 * times), the predicate context (class, subject, env), the plan, the revocation-state gate, the caveat language (K1, narrow,
 * max_uses), members a host callback replaced after the core checks, the core verdict as the pipeline reads it, and the
 * escalation path. Every expected value is traced through Authorize.run.
 */
public class AuthorizeRunK05bKillTest {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final String AUD = AuthorizeK05KillTest.AUD;
    static final Keys.SuiteKey PRINCIPAL = AuthorizeK05KillTest.PRINCIPAL, AGENT = AuthorizeK05KillTest.AGENT, CHILD = AuthorizeK05KillTest.key(33);
    static final String SALT = Pca.b64(new byte[16]);
    static final Map<String, Object> PARAMS = Map.of("amount", 50L);
    static final String GID = (String) AuthorizeK05KillTest.GRANT.get("id");

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    // ---- fixtures --------------------------------------------------------------------------------------------------------

    static List<Object> star() {
        List<Object> l = new ArrayList<>();
        l.add(Issue.obj("verb", "*"));
        return l;
    }

    /** A grant whose envelope carries {@code envCaveats} and {@code preds}, with {@code rootExtra} root caveats after the envelope. */
    static Map<String, Object> grant(List<Object> envCaveats, List<Object> preds, List<Object> rootExtra) {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("type", "envelope");
        env.put("goal_commit", Issue.goalCommit("pay invoices", SALT));
        env.put("predicates", preds);
        env.put("caveats", envCaveats);
        env.put("risk_policy", Issue.defaultRiskPolicy());
        env.put("agent_binding", new LinkedHashMap<String, Object>());
        List<Object> cavs = new ArrayList<>();
        cavs.add(env);
        if (rootExtra != null) cavs.addAll(rootExtra);
        return Issue.mintRoot(PRINCIPAL, AGENT.id(), null, cavs);
    }

    static Map<String, Object> grant(Object... envCaveats) { return grant(new ArrayList<>(Arrays.asList(envCaveats)), star(), null); }

    static Agent agent(Map<String, Object> g) { return Agent.create(AGENT, AUD, g, null).clock(() -> NOW); }

    static Map<String, Object> act(Agent a) { return a.act("payments.send", "payments/acme", Issue.obj("amount", 50L)); }

    static Map<String, Object> act(Map<String, Object> g) { return act(agent(g)); }

    static Map<String, Object> pcactn() { return AuthorizeK05KillTest.pcactn(); }

    static Authorize.Input input() { return AuthorizeK05KillTest.input(PARAMS); }

    static Authorize.Input in(Map<String, Object> g) { return input().resolveGrant(ref -> ref.equals(g.get("id")) ? g : null); }

    static Authorize.AuthorizeResult run(Object pc, Authorize.Input in) { return Authorize.authorize(pc, in); }

    static Map<String, Object> ctx(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static Map<String, Object> maxUses(String id) { return Issue.obj("type", "max_uses", "id", id, "n", 1L, "until", NOW + 3_600_000L); }

    /** A grant with a root max_uses caveat after its envelope. */
    static Map<String, Object> usesGrant() { return grant(new ArrayList<>(), star(), List.<Object>of(maxUses("m1"))); }

    static Map<String, Object> allowWhere(Object... conds) {
        return Issue.obj("type", "predicates", "allow", List.<Object>of(Issue.obj("verb", "*", "where", new ArrayList<>(Arrays.asList(conds)))));
    }

    /** A copy of a PCActn whose action, plan and cap_chain a callback may edit in place. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> mutable(Map<String, Object> pc) {
        Map<String, Object> m = new LinkedHashMap<>(pc);
        m.put("action", new LinkedHashMap<>((Map<String, Object>) pc.get("action")));
        m.put("plan", new LinkedHashMap<>((Map<String, Object>) pc.get("plan")));
        m.put("cap_chain", new ArrayList<>((List<Object>) pc.get("cap_chain")));
        return m;
    }

    /** A revocation check (it runs right after the core checks) that edits the PCActn first. */
    static Authorize.RevocationCheck after(Consumer<Map<String, Object>> edit) {
        return (p, g) -> {
            edit.accept(p);
            return false;
        };
    }

    static void noError(Authorize.AuthorizeResult r) {
        assertNotNull(r);
        assertFalse(r.checks.containsKey("authorize"), String.valueOf(r.reasons));
    }

    static void allowed(Authorize.AuthorizeResult r) {
        assertNotNull(r);
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("allow", r.decision);
        assertEquals(List.of(), r.reasons);
    }

    static void denied(Authorize.AuthorizeResult r, String... reasons) {
        assertNotNull(r);
        assertFalse(r.allow);
        assertEquals("deny", r.decision, r.reasons.toString());
        assertEquals(Arrays.asList(reasons), r.reasons);
    }

    // ---- the stock caveat context and the predicate context --------------------------------------------------------------

    @Test void theCaveatContextCarriesNowDepthBlastRadiusClassAndRecentTimes() {
        Map<String, Object> g = grant(Issue.obj("type", "expires", "at", NOW + 60_000L), Issue.obj("type", "delegation_depth", "max", 0L),
            Issue.obj("type", "max_blast_radius", "max", 10L), Issue.obj("type", "reversibility_max", "class", "reversible"),
            Issue.obj("type", "rate", "max", 1L, "per_secs", 60L));
        Map<String, Object> pc = act(g);
        allowed(run(pc, in(g).context(p -> ctx("blast_radius", 5L, "recent_action_times", List.of()))));
        denied(run(pc, in(g)), "policy: caveat(s) not satisfied: max_blast_radius, rate");
    }

    @Test void theDelegationDepthCountsTheHopsBelowTheRoot() {
        Map<String, Object> g0 = grant(Issue.obj("type", "delegation_depth", "max", 0L));
        denied(run(act(agent(g0).delegate(CHILD, new ArrayList<>())), in(g0)), "policy: caveat(s) not satisfied: delegation_depth");
        Map<String, Object> g1 = grant(Issue.obj("type", "delegation_depth", "max", 1L));
        allowed(run(act(agent(g1).delegate(CHILD, new ArrayList<>())), in(g1)));
    }

    @Test void theActionContextCarriesTheClassTheSubjectAndNoEnvWhenTheHostHasNone() {
        Map<String, Object> g = grant(allowWhere(Issue.obj("field", "action.reversibility_class", "op", "eq", "value", "reversible"),
            Issue.obj("field", "subject.id", "op", "eq", "value", "u1"), Issue.obj("field", "env", "op", "exists", "value", false)));
        Map<String, Object> pc = act(g);
        allowed(run(pc, in(g).context(p -> ctx("subject", Map.of("id", "u1")))));
        denied(run(pc, in(g)), "policy: caveat(s) not satisfied: predicates");
    }

    @Test void aGrantReadingAWorldPathWithNoSingleSourceRunsNoModelRule() {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*", "where", List.<Object>of(Issue.obj("field", "env.world.x", "op", "exists", "value", false))));
        Map<String, Object> g = grant(new ArrayList<>(), preds, null);
        allowed(run(act(g), in(g)));
    }

    // ---- the plan, the grant, zk -----------------------------------------------------------------------------------------

    @Test void theKnownPlanHashesEachNodesConditionsAndNeedsTheAuthorization() {
        Map<String, Object> g = grant();
        Agent a = agent(g);
        Map<String, Object> node = Issue.obj("id", "a", "verb", "payments.send", "resource", "payments/acme",
            "params_digest", Pca.paramsDigest(Issue.obj("amount", 50L)), "pre", List.of("x"), "post", List.of("y"));
        a.commitPlan(List.of(node));
        Map<String, Object> pc = a.actNode("a", Issue.obj("amount", 50L));
        allowed(run(pc, in(g).plan(null).context(p -> ctx("plan", List.of(node), "plan_authorized", true))));
        denied(run(pc, in(g).plan(null).context(p -> ctx("plan", List.of(node), "plan_authorized", false))),
            "plan_root_authorized: the plan root has not been authorized by the principal");
    }

    @Test void aGrantWithAnotherIdFailsGrantRef() {
        Map<String, Object> other = new LinkedHashMap<>(AuthorizeK05KillTest.GRANT);
        other.put("id", Pca.b64(new byte[32]));
        Authorize.AuthorizeResult r = run(pcactn(), input().resolveGrant(ref -> other));
        noError(r);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("grant_ref"));
        assertTrue(r.reasons.contains("grant_ref: does not reference the supplied grant"), r.reasons.toString());
    }

    @Test void aGrantWhoseCaveatsAreNotAListIsJudgedNotThrown() {
        Map<String, Object> odd = new LinkedHashMap<>(AuthorizeK05KillTest.GRANT);
        odd.put("caveats", "x");
        Authorize.AuthorizeResult r = run(pcactn(), input().resolveGrant(ref -> odd));
        noError(r);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("delegated_caveats"));
        // no grant caveat list: every leaf caveat (the envelope) counts as added by a hop
        assertTrue(r.reasons.contains("delegated_caveats: delegation caveat(s) not satisfied: envelope"), r.reasons.toString());
        assertTrue(r.reasons.contains("policy: grant carries no valid envelope"), r.reasons.toString());
    }

    @Test void aCarriedZkProofFailsClosed() {
        Map<String, Object> pc = new LinkedHashMap<>(pcactn());
        pc.put("zk_compliance", new LinkedHashMap<String, Object>());
        Authorize.AuthorizeResult r = run(pc, input());
        noError(r);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("zk_compliance"));
    }

    @Test void aRequiredCheckThatIsNotEnforcedIsNamedWithItsStatus() {
        denied(run(pcactn(), input().revocationStaleness(policy()).require("freshness")),
            "freshness: required check is not-enforced (default-deny: not enforced by this resource server)");
    }

    // ---- the revocation-state gate ---------------------------------------------------------------------------------------

    static RevocationStaleness policy() { return new RevocationStaleness().maxRevocationAgeMs(300_000); }

    static RevocationStaleness.State freshRoot() { return RevocationStaleness.State.root("r", NOW - 1_000L); }

    static Authorize.AuthorizeResult stale(Map<String, Object> pc, RevocationStaleness pol, Map<String, Object> c) {
        return run(pc, input().revocationStaleness(pol).context(p -> c));
    }

    @Test void withoutStateTheStricterOfTheSignedAndServerClassDecides() {
        Authorize.AuthorizeResult rev = stale(pcactn(), policy(), ctx());
        allowed(rev);
        assertEquals("not-enforced", rev.checks.get("freshness"));
        Authorize.AuthorizeResult irr = stale(pcactn(), policy(), ctx("reversibility_class", "irreversible"));
        assertEquals("fail", irr.checks.get("freshness"));
        assertTrue(irr.reasons.contains("freshness: no verifiable (guardian-signed) revocation state for an irreversible action"), irr.reasons.toString());
    }

    @Test void aBareRootIsHeldToTheSignedAndTheServerClass() {
        Authorize.AuthorizeResult rev = stale(pcactn(), policy().ids(p -> List.of()), ctx("revocation_state", freshRoot()));
        allowed(rev);
        assertEquals("pass", rev.checks.get("freshness"));
        Authorize.AuthorizeResult irr = stale(pcactn(), policy().ids(p -> List.of()), ctx("revocation_state", freshRoot(), "reversibility_class", "irreversible"));
        assertEquals("fail", irr.checks.get("freshness"));
        assertTrue(irr.reasons.contains("freshness: unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)"),
            irr.reasons.toString());
    }

    @Test void everyCapabilityInTheChainNeedsANonMembershipProof() {
        Map<String, Object> c = ctx("revocation_state", freshRoot());
        denied(stale(pcactn(), policy(), c), "freshness: no non-membership proof for " + GID);
        denied(stale(pcactn(), policy().ids(p -> List.of("cap-x")), c), "freshness: no non-membership proof for cap-x");
        denied(stale(pcactn(), policy().ids(p -> { throw new IllegalStateException("down"); }), c), "freshness: no non-membership proof for ");
    }

    static Authorize.AuthorizeResult staleAfter(Consumer<Map<String, Object>> edit) {
        return run(mutable(pcactn()), input().revocationStaleness(policy()).context(p -> ctx("revocation_state", freshRoot())).isRevoked(after(edit)));
    }

    /** A map whose {@code id} cannot be read. */
    static Map<String, Object> unreadableId() {
        return new AbstractMap<String, Object>() {
            @Override public Set<Map.Entry<String, Object>> entrySet() { return Set.of(); }
            @Override public Object get(Object k) {
                if ("id".equals(k)) throw new IllegalStateException("id");
                return null;
            }
        };
    }

    @Test void theProvedIdsAreReadFromTheChainAsItIsAfterTheCoreChecks() {
        // no chain list: nothing to prove; the chain is then empty, so there is no counter stream either
        Authorize.AuthorizeResult none = staleAfter(p -> p.put("cap_chain", "x"));
        denied(none, "replay: no counter stream for this proof (fail closed)");
        assertEquals("pass", none.checks.get("freshness"));
        String malformed = "delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>";
        // a hop that is no object, or whose id is no string, proves the empty id (after the ones before it)
        denied(staleAfter(p -> p.put("cap_chain", new ArrayList<Object>(List.of(Issue.obj("id", "a"), "x")))),
            "freshness: no non-membership proof for a", malformed);
        denied(staleAfter(p -> p.put("cap_chain", new ArrayList<Object>(List.of(Issue.obj("id", "a"), Issue.obj("id", 5L))))),
            "freshness: no non-membership proof for a", malformed);
        // an id that cannot be read: the whole list is the empty id (fail closed)
        denied(staleAfter(p -> p.put("cap_chain", new ArrayList<Object>(List.of(Issue.obj("id", "a"), unreadableId())))),
            "freshness: no non-membership proof for ", malformed);
    }

    static Map<String, Object> signedEpoch(String grantRef, long epoch) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", "i");
        body.put("grant_ref", grantRef);
        body.put("epoch", IntentJs.ofLong(epoch));
        body.put("set_size", IntentJs.ofLong(0));
        body.put("root", "r");
        body.put("issued_at", IntentJs.ofLong(NOW - 1_000));
        body.put("not_after", IntentJs.ofLong(NOW - 1_000 + 600_000));
        byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(body));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(StalenessVectorsTest.seed("staleness/guardian"), 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", StalenessVectorsTest.pub());
        ep.put("sig", Pca.b64(sig));
        return ep;
    }

    @Test void aSignedEpochIsHeldToTheProofsFreshnessEpoch() {
        RevocationStaleness pol = new RevocationStaleness().guardianPublic(StalenessVectorsTest.pub()).ids(p -> List.of());
        Map<String, Object> pc = pcactn(); // freshness.epoch 0
        String gref = (String) pc.get("grant_ref");
        Authorize.AuthorizeResult same = stale(pc, pol, ctx("revocation_state", RevocationStaleness.State.epoch(signedEpoch(gref, 0), null, null)));
        allowed(same);
        assertEquals("pass", same.checks.get("freshness"));
        Map<String, Object> newer = ctx("revocation_state", RevocationStaleness.State.epoch(signedEpoch(gref, 1), null, null));
        denied(stale(pc, pol, newer), "freshness: PCActn freshness.epoch 0 predates the revocation epoch 1");
        // the freshness member replaced after the core checks: no proof epoch to compare, the signed state alone decides
        Authorize.AuthorizeResult gone = run(mutable(pc), input().revocationStaleness(pol).context(p -> newer).isRevoked(after(p -> p.put("freshness", "x"))));
        allowed(gone);
        assertEquals("pass", gone.checks.get("freshness"));
    }

    // ---- members replaced after the core checks --------------------------------------------------------------------------

    @Test void anActionOrPlanReplacedAfterTheCoreChecksIsReadAsEmpty() {
        Authorize.AuthorizeResult a = run(mutable(pcactn()), input().revocationStaleness(policy()).isRevoked(after(p -> p.put("action", "x"))));
        noError(a);
        assertFalse(a.allow);
        assertEquals("fail", a.checks.get("operation"));
        // no signed class: the most restrictive one
        assertEquals("fail", a.checks.get("freshness"));
        assertTrue(a.reasons.contains("freshness: no verifiable (guardian-signed) revocation state for an irreversible action"), a.reasons.toString());
        Authorize.AuthorizeResult q = run(mutable(pcactn()), input().isRevoked(after(p -> p.put("plan", "x"))));
        noError(q);
        assertFalse(q.allow);
        assertTrue(q.reasons.contains("plan_root_authorized: known plan does not match plan.root"), q.reasons.toString());
    }

    @Test void aChainEmptiedAfterTheCoreChecksHasNoCounterStream() {
        Authorize.AuthorizeResult r = run(mutable(pcactn()), input().k1(new LinkedHashMap<>()).isRevoked(after(p -> ((List<?>) p.get("cap_chain")).clear())));
        denied(r, "replay: no counter stream for this proof (fail closed)");
        assertEquals(403, r.status);
        assertEquals("fail", r.checks.get("replay"));
        assertFalse(r.checks.containsKey("delegated_caveats"), r.checks.toString());
    }

    @Test void anEmptiedChainStillJudgesTheGrantsK1Caveats() {
        Map<String, Object> g = usesGrant();
        Authorize.AuthorizeResult r = run(mutable(act(g)), in(g).isRevoked(after(p -> ((List<?>) p.get("cap_chain")).clear())));
        denied(r, "delegated_caveats: delegation caveat(s) not satisfied: max_uses (the caveat language is not configured (no k1 input))");
    }

    @SuppressWarnings("unchecked")
    @Test void aLeafReplacedAfterTheCoreChecksIsAMalformedCaveatList() {
        Authorize.AuthorizeResult r = run(mutable(pcactn()), input().isRevoked(after(p -> ((List<Object>) p.get("cap_chain")).set(0, "x"))));
        denied(r, "delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>");
    }

    /** Two plan nodes: the first (another resource) irreversible, the second (this action) reversible. */
    static final Map<String, Object> OTHER = Issue.obj("id", "o", "verb", "payments.send", "resource", "payments/other",
        "params_digest", Pca.paramsDigest(Issue.obj("amount", 50L)), "reversibility_class", "irreversible");
    static final Map<String, Object> MATCH = Issue.obj("id", "m", "verb", "payments.send", "resource", "payments/acme",
        "params_digest", Pca.paramsDigest(Issue.obj("amount", 50L)), "reversibility_class", "reversible");

    static Map<String, Object> twoNodeAct(Map<String, Object> g) {
        Agent a = agent(g);
        a.commitPlan(List.of(OTHER, MATCH));
        return a.actNode("m", Issue.obj("amount", 50L));
    }

    static Map<String, Object> revMax() { return Issue.obj("type", "reversibility_max", "class", "reversible"); }

    static final String REV_MAX_UNMET = "policy: caveat(s) not satisfied: reversibility_max";

    @SuppressWarnings("unchecked")
    static Authorize.AuthorizeResult noClass(Map<String, Object> g, Object plan, Consumer<Map<String, Object>> more) {
        return run(mutable(twoNodeAct(g)), in(g).plan(null).context(p -> ctx("plan", plan, "plan_authorized", true)).isRevoked(after(p -> {
            ((Map<String, Object>) p.get("action")).remove("reversibility_class");
            more.accept(p);
        })));
    }

    @SuppressWarnings("unchecked")
    @Test void withNoClassTheCaveatsReadTheMatchingPlanNodes() {
        // and the predicate context carries no class at all
        Map<String, Object> g = grant(revMax(), allowWhere(Issue.obj("field", "action.reversibility_class", "op", "exists", "value", false)));
        allowed(noClass(g, List.of(OTHER, MATCH), p -> { }));
        Map<String, Object> only = grant(revMax());
        // a plan entry that is no object is skipped
        Authorize.AuthorizeResult skip = noClass(only, List.of("junk", MATCH), p -> { });
        noError(skip);
        assertFalse(skip.reasons.contains(REV_MAX_UNMET), skip.reasons.toString());
        // no node id, or no plan list: no class
        Authorize.AuthorizeResult noId = noClass(only, List.of(OTHER, MATCH), p -> ((Map<String, Object>) p.get("plan")).remove("node_id"));
        noError(noId);
        assertTrue(noId.reasons.contains(REV_MAX_UNMET), noId.reasons.toString());
        Authorize.AuthorizeResult noList = noClass(only, "x", p -> { });
        noError(noList);
        assertTrue(noList.reasons.contains(REV_MAX_UNMET), noList.reasons.toString());
    }

    @Test void aSignedOrServerClassWinsOverThePlanNode() {
        Map<String, Object> g = grant(revMax());
        Authorize.AuthorizeResult r = run(twoNodeAct(g), in(g).plan(null)
            .context(p -> ctx("plan", List.of(OTHER, MATCH), "plan_authorized", true, "reversibility_class", "irreversible")));
        noError(r);
        assertTrue(r.reasons.contains(REV_MAX_UNMET), r.reasons.toString());
    }

    // ---- the caveat language ---------------------------------------------------------------------------------------------

    @Test void theMaxUsesLifecycle() {
        Map<String, Object> g = usesGrant();
        Map<String, Object> pc = act(g);
        denied(run(pc, in(g)), "delegated_caveats: delegation caveat(s) not satisfied: max_uses (the caveat language is not configured (no k1 input))");
        Authorize.AuthorizeResult noStore = run(pc, in(g).k1(new LinkedHashMap<>()));
        denied(noStore, "max_uses: the chain carries a max_uses caveat and this authorize call has no usesStore (fail closed)");
        assertEquals("fail", noStore.checks.get("max_uses"));
        assertEquals(403, noStore.status);
        MemoryStateStore uses = new MemoryStateStore();
        Agent a = agent(g);
        allowed(run(act(a), in(g).k1(new LinkedHashMap<>()).usesStore(uses)));
        denied(run(act(a), in(g).k1(new LinkedHashMap<>()).usesStore(uses)), "max_uses: max_uses 'm1' is exhausted");
    }

    @Test void aCaveatLanguageInputThatCannotBeReadFailsClosed() {
        Map<String, Object> g = usesGrant();
        Map<String, Object> boom = new AbstractMap<String, Object>() {
            @Override public Set<Map.Entry<String, Object>> entrySet() { throw new IllegalStateException("boom"); }
            @Override public boolean containsKey(Object k) { return false; }
        };
        denied(run(act(g), in(g).k1(boom)), "delegated_caveats: delegation caveat(s) not satisfied: <caveat language>",
            "policy: root caveat(s) not satisfied: max_uses");
    }

    @SuppressWarnings("unchecked")
    @Test void aVerifiedNarrowBlocksPlainCaveatsJoinTheDelegatedOnes() {
        Map<String, Object> g = grant();
        Map<String, Object> pc = act(g);
        Map<String, Object> leaf = (Map<String, Object>) ((List<Object>) pc.get("cap_chain")).get(0);
        Map<String, Object> narrow = Issue.narrow(AGENT, leaf, List.<Object>of(Issue.obj("type", "max_blast_radius", "max", 10L)),
            CaveatLang.dischargeActionDigest(pc), NOW - 1_000, NOW + 60_000);
        Map<String, Object> k1 = new LinkedHashMap<>();
        k1.put("narrow", narrow);
        allowed(run(pc, in(g).k1(k1).context(p -> ctx("blast_radius", 5L))));
        denied(run(pc, in(g).k1(k1).context(p -> ctx("blast_radius", 50L))), "delegated_caveats: delegation caveat(s) not satisfied: max_blast_radius");
        Map<String, Object> junk = new LinkedHashMap<>();
        junk.put("narrow", "junk");
        denied(run(pc, in(g).k1(junk)), "delegated_caveats: delegation caveat(s) not satisfied: narrow (malformed narrow block: not an object)");
    }

    @Test void aHopsAddedCaveatsAreJudgedAndItsK1OnesLeftToTheCaveatLanguage() {
        Map<String, Object> g = grant();
        Map<String, Object> pc = act(agent(g).delegate(CHILD, List.<Object>of(Issue.obj("type", "max_blast_radius", "max", 10L))));
        denied(run(pc, in(g).context(p -> ctx("blast_radius", 50L))), "delegated_caveats: delegation caveat(s) not satisfied: max_blast_radius");
        allowed(run(pc, in(g).context(p -> ctx("blast_radius", 5L))));
        Map<String, Object> pu = act(agent(g).delegate(CHILD, List.<Object>of(maxUses("h1"))));
        allowed(run(pu, in(g).k1(new LinkedHashMap<>()).usesStore(new MemoryStateStore())));
    }

    // ---- the core verdict as the pipeline reads it (test seam) -----------------------------------------------------------

    @Test void aWireFailureWithoutAReasonIsNamedMalformed() {
        for (String why : Arrays.asList("", null)) {
            Authorize.coreHook = core -> {
                core.checks.put("wire", false);
                core.allow = false;
                core.reason = why;
            };
            Authorize.AuthorizeResult r = run(pcactn(), input());
            assertEquals(401, r.status);
            assertEquals(Map.of("wire", "fail", "malformed", "fail"), r.checks);
            assertEquals(List.of("wire: malformed PCActn"), r.reasons);
            assertEquals("wire: malformed PCActn", r.reason);
        }
    }

    @Test void onlyARefusingCoreWithAReasonAddsIt() {
        for (String why : Arrays.asList("", null)) {
            Authorize.coreHook = core -> {
                core.checks.put("version", false);
                core.allow = false;
                core.reason = why;
            };
            Authorize.AuthorizeResult r = run(pcactn(), input());
            noError(r);
            assertEquals("fail", r.checks.get("version"));
            assertEquals("deny", r.decision);
            assertEquals(List.of(), r.reasons);
        }
        Authorize.coreHook = core -> core.reason = "x";
        allowed(run(pcactn(), input()));
    }

    // ---- escalation ------------------------------------------------------------------------------------------------------

    /** Every core check passes except an escalate-class one (not provenance, so an undo window may lift it). */
    static void escalate() {
        Authorize.coreHook = core -> {
            for (String k : new ArrayList<>(core.checks.keySet())) core.checks.put(k, true);
            core.checks.put("classes", false);
            core.allow = false;
            core.reason = "classes: intent_required: a question is required";
        };
    }

    static final String ESCALATE_REASON = "classes: intent_required: a question is required";

    static Map<String, Object> junkAnswer() {
        Map<String, Object> junk = new LinkedHashMap<>();
        junk.put("junk", 1L);
        return junk;
    }

    @Test void aCounterTheStreamHasNotPassedEscalates() {
        escalate();
        MemoryStateStore store = new MemoryStateStore();
        assertTrue(store.claim(Authorize.stateKey(GID, AGENT.id()), 0L).ok);
        Authorize.AuthorizeResult r = run(pcactn(), input().stateStore(store));
        assertEquals("escalate", r.decision, r.reasons.toString());
        assertEquals(List.of(ESCALATE_REASON), r.reasons);
        assertEquals(Escalation.historyHead(0L), r.escalation.get("history_head"));
    }

    static final class LastDown implements StateStore, LastStore {
        final MemoryStateStore m = new MemoryStateStore();
        @Override public StateStore.ClaimResult claim(String key, long counter) { return m.claim(key, counter); }
        @Override public Long last(String key) { throw new IllegalStateException("down"); }
    }

    @Test void anUnreadableHistoryHeadNeverJudgesAnAnswer() {
        escalate();
        Authorize.AuthorizeResult r = run(pcactn(), input().stateStore(new LastDown()).escalationAnswer(junkAnswer()).insecureUnboundApproval(true));
        assertEquals("escalate", r.decision, r.reasons.toString());
        assertEquals(List.of(ESCALATE_REASON), r.reasons);
    }

    @Test void anEscalationRequestThatCannotBeBuiltDenies() {
        escalate();
        Map<String, Object> g = new LinkedHashMap<>(AuthorizeK05KillTest.GRANT);
        g.put("x", new Object()); // the policy digest cannot be computed
        Authorize.AuthorizeResult r = run(pcactn(), input().resolveGrant(ref -> g));
        assertNotNull(r);
        assertFalse(r.allow);
        assertEquals("deny", r.decision);
        assertNull(r.escalation);
        assertEquals(List.of(ESCALATE_REASON), r.reasons);
    }

    static Map<String, Object> admission() {
        return Issue.obj("id", "u1", "window_end", NOW + 60_000L, "compensation", Issue.obj("verb", "payments.refund"));
    }

    @Test void onlyAnUnansweredEscalationRunsUnderTheUndoWindow() {
        escalate();
        Authorize.AuthorizeResult open = run(pcactn(), input().undo((p, g, op) -> admission()));
        assertTrue(open.allow, open.reasons.toString());
        assertNotNull(open.undo);
        assertEquals("pass", open.checks.get("undo_window"));
        Authorize.AuthorizeResult answered = run(pcactn(), input().escalationAnswer(junkAnswer()).insecureUnboundApproval(true).undo((p, g, op) -> admission()));
        assertFalse(answered.allow);
        assertEquals("escalate", answered.decision);
        assertNull(answered.undo);
        assertFalse(answered.checks.containsKey("undo_window"));
    }

    @Test void aGrantIdChangedBeforeTheDecisionHasNoCounterStream() {
        // the grant passed grant_ref; a gate callback then changed its id
        Map<String, Object> g = new LinkedHashMap<>(AuthorizeK05KillTest.GRANT);
        ArgProvenance.Options gate = ProvHarness.options().bundle((p, op) -> {
            g.put("id", 5L);
            return ProvHarness.bundle(op);
        });
        denied(run(pcactn(), input().resolveGrant(ref -> g).provenanceGate(gate)), "replay: no counter stream for this proof (fail closed)");
        escalate();
        Map<String, Object> g2 = new LinkedHashMap<>(AuthorizeK05KillTest.GRANT);
        ArgProvenance.Options gate2 = ProvHarness.options().bundle((p, op) -> {
            g2.put("id", 5L);
            return ProvHarness.bundle(op);
        });
        Authorize.AuthorizeResult r = run(pcactn(), input().resolveGrant(ref -> g2).provenanceGate(gate2));
        assertEquals("deny", r.decision, r.reasons.toString());
        assertNull(r.escalation);
        assertEquals(List.of(ESCALATE_REASON), r.reasons);
    }
}
