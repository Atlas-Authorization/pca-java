package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills (round 5, tag G6, second part): Optimistic anonymous-challenge split, IntentJs / Json number printing,
 * IntentWB context shape over immutable maps, IntentRevocation (epoch shape, equivocation clause with a tracked last epoch, self-signed
 * epochs), IntentMap cell/arity, IntentSession layers.org, Predicates.firstUnmetLimit with malformed verbs, and Pca.verifyPcactn reason
 * precedence. Keys are generated at load from fixed seeds (never stored).
 */
public class K05R5G6DeepTest {

    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> obj(Object... kv) { return MeshK05KillTest.obj(kv); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    static Object j(String text) { return Json.parseLenient(text); }

    // ---- Optimistic.settlementWireCheck: the anonymous-challenge split ----

    @Test void anonymousChallengeSplitSendsEverythingToTheTreasury() {
        String head = Track3KillTest.SLASH;
        String tail = ",\"victimAccount\":\"v\",\"treasuryAccount\":\"t\",\"challengerAccount\":null}}";
        String all = "{\"amount\":100,\"challengerReward\":0,\"victimCompensation\":0,\"treasuryRemainder\":100" + tail;
        assertEquals("signature", Optimistic.settlementWireCheck(j(head + all), "k"));
        String vc = "{\"amount\":100,\"challengerReward\":0,\"victimCompensation\":20,\"treasuryRemainder\":80" + tail;
        assertEquals("split", Optimistic.settlementWireCheck(j(head + vc), "k"));
        String cr = "{\"amount\":100,\"challengerReward\":10,\"victimCompensation\":0,\"treasuryRemainder\":90" + tail;
        assertEquals("split", Optimistic.settlementWireCheck(j(head + cr), "k"));
        String tr = "{\"amount\":100,\"challengerReward\":0,\"victimCompensation\":0,\"treasuryRemainder\":99" + tail;
        assertEquals("split", Optimistic.settlementWireCheck(j(head + tr), "k"));
        String both = "{\"amount\":100,\"challengerReward\":5,\"victimCompensation\":5,\"treasuryRemainder\":90" + tail;
        assertEquals("split", Optimistic.settlementWireCheck(j(head + both), "k"));
        String named = "{\"amount\":100,\"challengerReward\":10,\"victimCompensation\":20,\"treasuryRemainder\":70,\"victimAccount\":\"v\",\"treasuryAccount\":\"t\",\"challengerAccount\":\"ch\"}}";
        assertEquals("signature", Optimistic.settlementWireCheck(j(head + named), "k"));
    }

    // ---- number printing ----

    @Test void largeNegativeIntegersPrintTheirShortestDigits() {
        // |d| >= 1e21: the shortest round-trip digits, not the exact binary expansion (which is only used below 1e21)
        assertEquals("-100000000000000000000000", IntentJs.normNum("-1e23").raw);
        assertEquals("100000000000000000000000", IntentJs.normNum("1e23").raw);
        assertEquals("-5", IntentJs.normNum("-5").raw);
    }

    @Test void shortestPicksTheOnlyDigitsThatReadBack() {
        // 2^-44: at 16 digits only the upper candidate reads back although the lower one is closer to the exact value
        double a = Math.pow(2, -44);
        assertEquals("0.00000000000005684341886080802", Json.shortest(a).toPlainString());
        assertEquals(a, Double.parseDouble(Json.shortest(a).toPlainString()));
        assertEquals("0.3", Json.shortest(0.3d).toPlainString());
        assertEquals("1.5", Json.shortest(1.5d).toPlainString());
        assertEquals("100", Json.shortest(100d).toPlainString());
    }

    // ---- IntentWB.contextError over immutable maps ----

    @Test void contextErrorNeverAsksAnImmutableMapForANullKey() {
        Map<String, Object> input = Map.of("intent_session", Map.of(), "artifacts", Map.of("facts", List.of()), "policy", Map.of("world", Map.of()));
        assertNull(IntentWB.contextError(input));
        Map<String, Object> input2 = Map.of("intent_session", Map.of(), "artifacts", Map.of("labels", List.of()), "policy", Map.of("provenance", Map.of()));
        assertNull(IntentWB.contextError(input2));
        Map<String, Object> bad = Map.of("intent_session", Map.of(), "artifacts", Map.of("verdicts", "x"));
        assertEquals("artifacts.verdicts must be an array", IntentWB.contextError(bad));
        Map<String, Object> badPolicy = Map.of("intent_session", Map.of(), "policy", Map.of("provenance", "x"));
        assertEquals("policy.provenance must be an object", IntentWB.contextError(badPolicy));
        Map<String, Object> badWorld = Map.of("intent_session", Map.of(), "policy", Map.of("world", List.of()));
        assertEquals("policy.world must be an object", IntentWB.contextError(badWorld));
    }

    // ---- IntentRevocation ----

    @Test void revocationEpochShapeOverAnImmutableMap() {
        Map<String, Object> ep = Map.of("instance_id", "i", "grant_ref", "g", "root", "r", "guardian", "k", "sig", "s",
            "epoch", n(1), "set_size", n(1), "issued_at", n(1), "not_after", n(2));
        assertNull(IntentRevocation.revocationEpochShapeError(ep));
        Map<String, Object> pq = new LinkedHashMap<>(ep);
        pq.put("pq_pk", n(1));
        assertEquals("revocation epoch pq_pk must be a string", IntentRevocation.revocationEpochShapeError(pq));
        pq.put("pq_pk", "x");
        pq.put("pq_sig", n(1));
        assertEquals("revocation epoch pq_sig must be a string", IntentRevocation.revocationEpochShapeError(pq));
    }

    @Test void templateTextOfNullIsNull() {
        assertEquals("null", IntentRevocation.jsText(null, true));
        assertEquals("undefined", IntentRevocation.jsText(null, false));
        assertEquals("a", IntentRevocation.jsText("a", true));
        assertEquals("1,,x", IntentRevocation.jsText(list(n(1), null, "x"), true));
    }

    static final K05R5G2MeshTest.Key GUARD = new K05R5G2MeshTest.Key("g6-revocation-guardian");
    static final String SESSION = "s1";

    static Map<String, Object> epoch(long no, List<String> revoked) {
        Map<String, Object> ep = obj("instance_id", "i1", "grant_ref", IntentRevocation.sessionRevocationScope(SESSION), "epoch", n(no), "set_size", n(revoked.size()),
            "root", IntentRevocation.revsetRoot(revoked), "issued_at", n(1000), "not_after", n(5000));
        Map<String, Object> body = new LinkedHashMap<>(ep);
        byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8),
            IntentJs.canonBytes(IntentJs.bindSuiteFields(body, null, false, null, false)));
        ep.put("guardian", GUARD.pub);
        ep.put("sig", GUARD.sign(msg));
        return ep;
    }
    static Map<String, Object> evidence(long no, String... revoked) {
        List<String> r = Arrays.asList(revoked);
        return obj("epoch", epoch(no, r), "revoked", new ArrayList<Object>(r));
    }
    static String check(Object ev, Object last, boolean lastPresent, String... ids) {
        return IntentRevocation.checkSessionRevocation(ev, SESSION, GUARD.pub, new ArrayList<Object>(Arrays.asList(ids)), 2000, 10000, null, null, lastPresent, last);
    }

    @Test void aTrackedLastEpochIsComparedByEpochNumber() {
        // growth by one id: a different epoch number, a different root: fine
        assertNull(check(evidence(1, "a"), evidence(0), true, "zzz"));
        // the very same epoch again: fine
        assertNull(check(evidence(1, "a"), evidence(1, "a"), true, "zzz"));
        assertNull(check(evidence(0), evidence(0), true, "zzz"));
        assertNull(check(evidence(2, "a", "b"), evidence(1, "a"), true, "zzz"));
        // no tracked epoch at all
        assertNull(check(evidence(1, "a"), null, false, "zzz"));
        // an older epoch than the tracked one
        assertEquals("revocation epoch rollback (older than the last accepted)", check(evidence(0), evidence(1, "a"), true, "zzz"));
        // the same number but another set: not append-only is reported first
        assertEquals("the epoch drops 'b', revoked in the last accepted epoch (not append-only)", check(evidence(1, "a"), evidence(1, "b"), true, "zzz"));
        // an id of the checked list that is revoked
        assertEquals("'a' is revoked", check(evidence(1, "a"), evidence(0), true, "a"));
        assertEquals("'a' is revoked", check(evidence(1, "a"), null, false, "zzz", "a"));
        // a malformed tracked epoch
        assertEquals("the tracked last epoch is malformed (fail closed)", check(evidence(1, "a"), "x", true, "zzz"));
    }

    // ---- IntentMap: a cell leaf with more coordinates than the action's cell ----

    @Test void aCellWithTooManyCoordinatesIsNotTheActionsCell() {
        List<Object[]> leaves = new ArrayList<>(IntentMapKillTest.LEAVES);
        leaves.set(2, new Object[] {"cell", IntentMapKillTest.map("verb", "air.book", "cell", IntentMapKillTest.list(0L, 0L, 0L), "p_ppm", 1000L, "in_grant", true)});
        int size = leaves.size();
        List<byte[]> hs = new ArrayList<>();
        for (int i = 0; i < size; i++) hs.add(IntentMap.leafHash((String) leaves.get(i)[0], IntentMapKillTest.salt(i), IntentMapKillTest.deep(leaves.get(i)[1])));
        String commit = IntentMap.commitOf(size, IntentMapKillTest.root(hs));
        Map<String, Object> disclosure = IntentMapKillTest.map("size", (long) size, "header", entry(leaves, hs, 0), "cell", entry(leaves, hs, 2), "metrics", entry(leaves, hs, size - 2));
        Map<String, Object> params = IntentMapKillTest.params(38_900L, "economy");
        Map<String, Object> action = IntentMapKillTest.map("verb", "air.book", "resource", "r", "params_digest", Pca.paramsDigest(IntentMapKillTest.deep(params)));
        IntentMap.Decision d = IntentMap.decide(commit, IntentMapKillTest.deep(action), true, IntentMapKillTest.deep(params), IntentMapKillTest.deep(disclosure), null);
        assertFalse(d.ok);
        assertEquals("the disclosed cell is not the action's cell", d.reason);
    }

    static Map<String, Object> entry(List<Object[]> leaves, List<byte[]> hs, int i) {
        List<Object> p = new ArrayList<>();
        IntentMapKillTest.path(hs, i, p);
        return IntentMapKillTest.map("index", (long) i, "salt", Pca.b64(IntentMapKillTest.salt(i)), "leaf", leaves.get(i)[1], "path", p);
    }

    // ---- IntentSession: the optional org layer ----

    @SuppressWarnings("unchecked")
    static Map<String, Object> baseRoot() throws Exception {
        Map<String, Object> cases = (Map<String, Object>) Json.parseLenient(new String(Files.readAllBytes(Path.of("test-data/k042-sessrevoc-cases.json")), StandardCharsets.UTF_8));
        for (Object c : (List<Object>) cases.get("root")) {
            Map<String, Object> m = (Map<String, Object>) c;
            if (m.get("shape") == null && "ok".equals(m.get("name"))) return (Map<String, Object>) IntentJs.normalize(Json.parseLenient((String) m.get("s")));
        }
        throw new IllegalStateException("no base root");
    }
    @SuppressWarnings("unchecked") static Map<String, Object> layers(Map<String, Object> root) { return (Map<String, Object>) root.get("layers"); }

    @Test void theOrgLayerIsOptionalButClosed() throws Exception {
        Map<String, Object> r = baseRoot();
        assertFalse(layers(r).containsKey("org"));
        assertNull(IntentSession.rootShapeError(r));
        String msg = "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)";
        layers(r).put("org", obj("digest", Pca.b64(new byte[32])));
        assertNull(IntentSession.rootShapeError(r));
        layers(r).put("org", null);
        assertEquals(msg, IntentSession.rootShapeError(r));
        layers(r).put("org", obj("digest", "x"));
        assertEquals(msg, IntentSession.rootShapeError(r));
        layers(r).put("org", "x");
        assertEquals(msg, IntentSession.rootShapeError(r));
        layers(r).put("org", obj());
        assertEquals(msg, IntentSession.rootShapeError(r));
    }

    // ---- Predicates.firstUnmetLimit: a predicate whose verb is malformed does not end the search ----

    @Test void aMalformedVerbSkipsOnlyThatPredicate() {
        Map<String, Object> ctx = (Map<String, Object>) j("{\"action\":{\"verb\":\"pay\",\"resource\":\"acct/1\",\"params\":{\"amount\":500}}}");
        String limit = "{\"verb\":\"pay\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":100}]}";
        for (String badVerb : new String[] {"5", "null", "true", "{}"}) {
            String preds = "[{\"verb\":" + badVerb + ",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}," + limit + "]";
            assertEquals("amount <= 100", Predicates.firstUnmetLimit(j(preds), ctx), badVerb);
        }
        String missing = "[{\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}," + limit + "]";
        assertEquals("amount <= 100", Predicates.firstUnmetLimit(j(missing), ctx));
        String list = "[{\"verb\":[5,\"x\"],\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}," + limit + "]";
        assertEquals("amount <= 100", Predicates.firstUnmetLimit(j(list), ctx));
        String match = "[{\"verb\":[5,\"pay\"],\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}]";
        assertEquals("amount <= 1", Predicates.firstUnmetLimit(j(match), ctx));
    }

    // ---- Pca.verifyPcactn: the first failure keeps the verdict's reason ----

    static String flip(String sig) { return (sig.charAt(0) == 'A' ? "B" : "A") + sig.substring(1); }

    @SuppressWarnings("unchecked")
    static Object deepCopy(Object o) { return IntentJs.normalize(Json.parseLenient(Json.canonicalize(o))); }

    @SuppressWarnings("unchecked")
    static Pca.Verdict verdict(Map<String, Object> vec, Map<String, Object> pcactn) {
        return Pca.verifyPcactn(pcactn, FreshAtForwardTest.grant(vec), Json.asLong(FreshAtForwardTest.ctx(vec).get("now")), (String) FreshAtForwardTest.ctx(vec).get("aud"),
            null, null, null, FreshAtForwardTest.policy(vec), Pca.PlanRoots.SKIP);
    }

    @SuppressWarnings("unchecked")
    @Test void anEarlierFailureOutranksAFreshAtFailure() {
        Map<String, Object> vec = FreshAtForwardTest.vec("member-stale-revocation_epoch");
        Pca.Verdict alone = verdict(vec, (Map<String, Object>) vec.get("pcactn"));
        assertFalse(alone.allow);
        assertEquals(Boolean.FALSE, alone.checks.get("fresh_at"));
        assertTrue(alone.reason.startsWith("fresh_at: escalate: stale_state"), alone.reason);
        Map<String, Object> tampered = (Map<String, Object>) deepCopy(vec.get("pcactn"));
        tampered.put("sig", flip((String) tampered.get("sig")));
        Pca.Verdict v = verdict(vec, tampered);
        assertFalse(v.allow);
        assertEquals(Boolean.FALSE, v.checks.get("leaf_signature"));
        assertEquals(Boolean.FALSE, v.checks.get("fresh_at"));
        assertTrue(v.reason.startsWith("leaf_signature:"), v.reason);
    }

    @SuppressWarnings("unchecked")
    @Test void anEarlierFailureOutranksAnUnverifiedZkProof() {
        Map<String, Object> vec = FreshAtForwardTest.vec("member-equal-state");
        Map<String, Object> zk = (Map<String, Object>) deepCopy(vec.get("pcactn"));
        zk.put("zk_compliance", obj());
        zk.put("sig", flip((String) zk.get("sig")));
        Pca.Verdict v = verdict(vec, zk);
        assertFalse(v.allow);
        assertEquals(Boolean.FALSE, v.checks.get("zk_compliance"));
        assertEquals(Boolean.FALSE, v.checks.get("leaf_signature"));
        assertTrue(v.reason.startsWith("leaf_signature:"), v.reason);
        // alone, the unverified proof is the reason
        Map<String, Object> only = (Map<String, Object>) deepCopy(vec.get("pcactn"));
        only.put("zk_compliance", obj());
        Pca.Verdict w = verdict(vec, only);
        assertFalse(w.allow);
        assertEquals(Boolean.FALSE, w.checks.get("zk_compliance"));
        assertNotNull(w.reason);
    }
}
