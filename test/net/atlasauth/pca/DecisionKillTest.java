package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Exact-outcome kill tests for {@link Decision} and {@link Escalation}: every boundary and every reason text. */
public class DecisionKillTest {
    static Map<String, Object> jm(String s) { return AuthorizeFixtures.jm(s); }
    static Object j(String s) { return AuthorizeFixtures.j(s); }

    // ---- the lattice ----

    @Test void meetIsTheMinimumAndUnknownIsDeny() {
        String[] ds = {"deny", "escalate", "allow"};
        for (int i = 0; i < 3; i++)
            for (int k = 0; k < 3; k++) assertEquals(ds[Math.min(i, k)], Decision.meet(ds[i], ds[k]), ds[i] + "/" + ds[k]);
        assertEquals("deny", Decision.meet("allow", "bogus"));
        assertEquals("deny", Decision.meet("bogus", "allow"));
        assertEquals("deny", Decision.meet(null, "allow"));
        assertEquals("deny", Decision.meet("allow", null));
        assertEquals("deny", Decision.meet("bogus", "bogus"));
    }

    @Test void signalCeilingAndTighten() {
        assertEquals("allow", Decision.signalCeiling("ok"));
        assertEquals("escalate", Decision.signalCeiling("escalate"));
        assertEquals("deny", Decision.signalCeiling("deny"));
        assertEquals("deny", Decision.signalCeiling("OK"));
        assertEquals("deny", Decision.signalCeiling(null));
        assertEquals("deny", Decision.signalCeiling(Boolean.TRUE));
        assertEquals("allow", Decision.tighten("allow", "ok"));
        assertEquals("escalate", Decision.tighten("escalate", "ok"));
        assertEquals("escalate", Decision.tighten("allow", "escalate"));
        assertEquals("deny", Decision.tighten("deny", "escalate"));
        assertEquals("deny", Decision.tighten("escalate", "deny"));
    }

    @Test void pepOnlyUpgradesAnAnsweredEscalate() {
        assertEquals("allow", Decision.pepDecision("escalate", true));
        assertEquals("escalate", Decision.pepDecision("escalate", false));
        assertEquals("deny", Decision.pepDecision("deny", true));
        assertEquals("deny", Decision.pepDecision("deny", false));
        assertEquals("allow", Decision.pepDecision("allow", false));
        assertEquals("bogus", Decision.pepDecision("bogus", true)); // not a decision: returned as is
        assertNull(Decision.pepDecision(null, false));
    }

    // ---- decisionOf ----

    static String dof(boolean allow, String checks, String... reasons) {
        Map<String, String> c = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : jm(checks).entrySet()) c.put(e.getKey(), (String) e.getValue());
        return Decision.decisionOf(allow, c, List.of(reasons));
    }

    @Test void decisionOfOverTheFullCheckSet() {
        assertEquals("allow", dof(true, "{'a':'fail'}"));
        assertEquals("deny", dof(false, "{}"));
        assertEquals("deny", dof(false, "{'a':'pass','b':'not-enforced'}"));
        assertEquals("escalate", dof(false, "{'a':'fail'}", "a: escalate: x"));
        assertEquals("escalate", dof(false, "{'a':'fail'}", "a: intent_required: x"));
        assertEquals("escalate", dof(false, "{'a':'fail','b':'pass'}", "a: escalate: x", "b: hard"));
        assertEquals("deny", dof(false, "{'a':'fail'}"), "an unexplained failure never escalates");
        assertEquals("deny", dof(false, "{'a':'fail'}", "a: hard"));
        assertEquals("deny", dof(false, "{'a':'fail'}", "a: escalate: x", "a: hard"), "one hard reason of the check makes it hard");
        assertEquals("deny", dof(false, "{'a':'fail','b':'fail'}", "a: escalate: x"), "b has no reason of its own");
        assertEquals("escalate", dof(false, "{'a':'fail','b':'fail'}", "a: escalate: x", "b: intent_required: y"));
        assertEquals("deny", dof(false, "{'a':'fail','b':'fail'}", "a: escalate: x", "b: hard"));
        assertEquals("deny", dof(false, "{'prov':'fail'}", "provenance: escalate: x"), "the head is '<check>: ' exactly");
        assertEquals("deny", dof(false, "{'a':'fail'}", "a:escalate: x"), "no space after the colon is not the head");
        assertEquals("deny", dof(false, "{'a':'fail'}", "a: xescalate: x"), "the prefix must start the body");
    }

    @Test void decisionOfOverAJsonVerdict() {
        assertEquals("allow", Decision.decisionOf(jm("{'allow':true}")));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false}")));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false,'checks':[]}")));
        assertEquals("escalate", Decision.decisionOf(jm("{'allow':'true','checks':{'a':'fail'},'reasons':['a: escalate: x']}")), "only the boolean true allows");
        assertEquals("escalate", Decision.decisionOf(jm("{'allow':false,'checks':{'a':'fail'},'reasons':['a: escalate: x',3,null]}")));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false,'checks':{'a':'fail'}}")));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false,'checks':{'a':'fail'},'reasons':'a: escalate: x'}")));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false,'checks':{'a':5},'reasons':[]}")));
    }

    // ---- rule 21 ----

    @Test void modelDerivedPaths() {
        List<String> none = List.of();
        for (String p : new String[] {"env.class.x", "env.prov.a.b", "env.judge", "env.class", "env.world.w"}) {
            boolean world = p.startsWith("env.world");
            assertEquals(!world, Decision.isModelDerivedPath(p, none), p);
        }
        assertTrue(Decision.isModelDerivedPath("env.world.w", List.of("w")));
        assertFalse(Decision.isModelDerivedPath("env.world.w", List.of("x")));
        assertTrue(Decision.isModelDerivedPath("env.world", List.of("w")));
        assertFalse(Decision.isModelDerivedPath("env.world", none));
        assertFalse(Decision.isModelDerivedPath("env", List.of("w")));
        assertFalse(Decision.isModelDerivedPath("env.acc.x", none));
        assertFalse(Decision.isModelDerivedPath("action.params.x", none));
        assertFalse(Decision.isModelDerivedPath("xenv.class.x", none));
        assertFalse(Decision.isModelDerivedPath("env.classy.x", none));
        assertFalse(Decision.isModelDerivedPath(null, none));
        assertFalse(Decision.isModelDerivedPath(5, none));
    }

    @Test void modelPathsAreSortedDeduplicatedAndFoundAnywhere() {
        List<?> lists = (List<?>) j("[[{'where':[{'field':'env.prov.b','op':'eq','value':1},{'all_of':[{'ref':'env.class.a'},{'any_of':[{'collection':'env.judge.z'}]},{'not':{'field':'env.class.a'}}]}]},"
            + "{'where':'nope'},3],'notalist',[{'verb':'*'}]]");
        assertEquals(List.of("env.class.a", "env.judge.z", "env.prov.b"), Decision.modelPathsRead(lists, List.of()));
        Object deep = j("{'field':'env.class.deep'}");
        for (int i = 0; i < 64; i++) deep = wrapNot(deep);
        assertEquals(List.of("env.class.deep"), Decision.modelPathsRead(List.of(List.of(Map.of("where", List.of(deep)))), List.of()), "depth 64 is still read");
        assertEquals(List.of(), Decision.modelPathsRead(List.of(List.of(Map.of("where", List.of(wrapNot(deep))))), List.of()), "depth 65 is not read");
    }

    static Object wrapNot(Object c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("not", c);
        return m;
    }

    @Test void tightenListErrorsAreExact() {
        assertEquals("tighten must be an array", Decision.tightenListError(null));
        assertEquals("tighten must be an array", Decision.tightenListError(j("{}")));
        assertNull(Decision.tightenListError(j("[]")));
        assertEquals("tighten[0] must be an object", Decision.tightenListError(j("[3]")));
        assertEquals("unknown member 'tighten[0].x'", Decision.tightenListError(j("[{'id':'a','when':{},'signal':'deny','x':1}]")));
        assertEquals("missing member 'tighten[0].signal'", Decision.tightenListError(j("[{'id':'a','when':{}}]")));
        assertEquals("tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$", Decision.tightenListError(j("[{'id':'A','when':{},'signal':'deny'}]")));
        assertEquals("tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$", Decision.tightenListError(j("[{'id':5,'when':{},'signal':'deny'}]")));
        assertNull(Decision.tightenListError(j("[{'id':'" + "a".repeat(64) + "','when':{},'signal':'deny'}]")));
        assertEquals("tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$", Decision.tightenListError(j("[{'id':'" + "a".repeat(65) + "','when':{},'signal':'deny'}]")));
        assertEquals("tighten[1].id 'a' is a duplicate", Decision.tightenListError(j("[{'id':'a','when':{},'signal':'deny'},{'id':'a','when':{},'signal':'deny'}]")));
        assertEquals("tighten[0].when must be a condition object", Decision.tightenListError(j("[{'id':'a','when':[],'signal':'deny'}]")));
        assertEquals("tighten[0].signal must be 'escalate' or 'deny'", Decision.tightenListError(j("[{'id':'a','when':{},'signal':'ok'}]")));
        assertNull(Decision.tightenListError(j("[{'id':'a','when':{},'signal':'escalate','reason':'" + "r".repeat(256) + "'}]")));
        assertEquals("tighten[0].reason must be a string of at most 256 characters",
            Decision.tightenListError(j("[{'id':'a','when':{},'signal':'deny','reason':'" + "r".repeat(257) + "'}]")));
        assertEquals("tighten[0].reason must be a string of at most 256 characters",
            Decision.tightenListError(j("[{'id':'a','when':{},'signal':'deny','reason':null}]")));
        List<Object> many = new ArrayList<>();
        for (int i = 0; i < 64; i++) many.add(jm("{'id':'r" + i + "','when':{},'signal':'deny'}"));
        assertNull(Decision.tightenListError(many));
        many.add(jm("{'id':'r64','when':{},'signal':'deny'}"));
        assertEquals("tighten has more than 64 rules", Decision.tightenListError(many));
    }

    @Test void tightenOutcomesAndReasons() {
        Decision.TightenResult r = Decision.decideTighten(jm("{'tighten':null}"));
        assertEquals("deny", r.outcome);
        assertEquals("malformed tighten list: tighten must be an array", r.reason);
        r = Decision.decideTighten(jm("{}"));
        assertEquals("ok", r.outcome);
        assertNull(r.reason);
        assertFalse(r.legacy);
        r = Decision.decideTighten(jm("{'polarity':null}"));
        assertEquals("deny", r.outcome);
        assertEquals("model_polarity must be 'legacy' when present", r.reason);
        r = Decision.decideTighten(jm("{'polarity':'strict'}"));
        assertEquals("model_polarity must be 'legacy' when present", r.reason);
        r = Decision.decideTighten(jm("{'polarity':'legacy'}"));
        assertEquals("ok", r.outcome);
        assertFalse(r.legacy, "legacy needs an offending path");
        String preds = "[[{'verb':'*','where':[{'field':'env.class.t','op':'eq','value':1},{'field':'env.prov.p','op':'eq','value':1}]}]]";
        r = Decision.decideTighten(jm("{'predicates':" + preds + "}"));
        assertEquals("deny", r.outcome);
        assertEquals(List.of("env.class.t", "env.prov.p"), r.offending);
        assertEquals("a grant's where reads model-derived path(s) env.class.t, env.prov.p: a model may only tighten (move them into tighten[]) (rule 21)", r.reason);
        r = Decision.decideTighten(jm("{'polarity':'legacy','predicates':" + preds + "}"));
        assertEquals("ok", r.outcome);
        assertTrue(r.legacy);
        r = Decision.decideTighten(jm("{'predicates':[[{'where':[{'field':'env.world.w','op':'eq','value':1}]}]],'single_source':['w',3]}"));
        assertEquals("deny", r.outcome);
        assertEquals(List.of("env.world.w"), r.offending);
        String fires = "{'id':'big','when':{'field':'action.params.n','op':'gt','value':5},'signal':'escalate'}";
        String ctx = "'context':{'action':{'params':{'n':9}}}";
        r = Decision.decideTighten(jm("{'tighten':[" + fires + "]," + ctx + "}"));
        assertEquals("escalate", r.outcome);
        assertEquals("escalate: asked by tighten rule 'big'", r.reason);
        r = Decision.decideTighten(jm("{'tighten':[" + fires.replace("'escalate'", "'deny'").replace("}", ",'reason':'why'}") + "]," + ctx + "}"));
        assertEquals("deny", r.outcome);
        assertEquals("denied by tighten rule 'big' (why)", r.reason);
        r = Decision.decideTighten(jm("{'tighten':[" + fires + "],'context':{'action':{'params':{'n':1}}}}"));
        assertEquals("ok", r.outcome);
        assertNull(r.reason);
        r = Decision.decideTighten(jm("{'tighten':[" + fires + "]}"));
        assertEquals("escalate", r.outcome);
        assertEquals("escalate: rule 'big' could not be decided (a value it reads is missing or ill-typed)", r.reason);
        r = Decision.decideTighten(jm("{'tighten':[" + fires + "]," + ctx.replace("{'action'", "5,'x':{'action'") + "}"));
        assertEquals("escalate", r.outcome, "a non-object context is empty");
    }

    @Test void tightenKeepsTheStrictestSignalAndTheFirstReasonOfAnEqualOne() {
        String a = "{'id':'a','when':{'field':'action.params.n','op':'gt','value':1},'signal':'escalate'}";
        String b = "{'id':'b','when':{'field':'action.params.n','op':'gt','value':1},'signal':'escalate'}";
        String d = "{'id':'d','when':{'field':'action.params.n','op':'gt','value':1},'signal':'deny'}";
        String e = "{'id':'e','when':{'field':'action.params.n','op':'gt','value':1},'signal':'deny'}";
        String ctx = ",'context':{'action':{'params':{'n':9}}}";
        Decision.TightenResult r = Decision.decideTighten(jm("{'tighten':[" + a + "," + b + "]" + ctx + "}"));
        assertEquals("escalate: asked by tighten rule 'a'", r.reason);
        r = Decision.decideTighten(jm("{'tighten':[" + a + "," + d + "," + e + "," + b + "]" + ctx + "}"));
        assertEquals("deny", r.outcome);
        assertEquals("denied by tighten rule 'd'", r.reason);
        r = Decision.decideTighten(jm("{'tighten':[" + d + "," + a + "]" + ctx + "}"));
        assertEquals("denied by tighten rule 'd'", r.reason, "an escalate never relaxes a deny");
    }

    // ---- rule 20 ----

    static final String SU = "'schema_units':{'m':{'kind':'money','currency':'USD','exponent':2}},'verb_params':{'action.params.amount':{'unit':'m'},'action.params.note':{}},'verb':'refund'";

    static Decision.UnitsResult units(String tags, String rest) { return Decision.decideUnits(jm("{'units':" + tags + "," + rest + "}")); }

    @Test void unitTagShapeBoundaries() {
        String ok = "{'action.params.amount':{'kind':'money','currency':'USD','exponent':2}}";
        assertTrue(units(ok, SU).ok);
        assertNull(units(ok, SU).reason);
        for (String ex : new String[] {"0", "18"}) assertNull(Decision.unitTagsError(j("{'action.params.a':{'kind':'k','exponent':" + ex + "}}")), ex);
        for (String ex : new String[] {"-1", "19", "1.5", "'2'", "null"})
            assertEquals("units['action.params.a'].exponent must be an integer in [0, 18]",
                Decision.unitTagsError(j("{'action.params.a':{'kind':'k','exponent':" + ex + "}}")), ex);
        assertNull(Decision.unitTagsError(j("{'action.params.a':{'kind':'" + "k".repeat(64) + "'}}")));
        assertEquals("units['action.params.a'].kind must be a string of 1..64 characters", Decision.unitTagsError(j("{'action.params.a':{'kind':'" + "k".repeat(65) + "'}}")));
        assertEquals("units['action.params.a'].kind must be a string of 1..64 characters", Decision.unitTagsError(j("{'action.params.a':{'kind':''}}")));
        assertNull(Decision.unitTagsError(j("{'action.params.a':{'kind':'k','currency':'" + "c".repeat(16) + "'}}")));
        assertEquals("units['action.params.a'].currency must be a string of 1..16 characters", Decision.unitTagsError(j("{'action.params.a':{'kind':'k','currency':'" + "c".repeat(17) + "'}}")));
        assertEquals("units['action.params.a'].currency must be a string of 1..16 characters", Decision.unitTagsError(j("{'action.params.a':{'kind':'k','currency':''}}")));
        assertEquals("units must be an object", Decision.unitTagsError(null));
        assertEquals("units must be an object", Decision.unitTagsError(j("[]")));
        assertEquals("units key 'amount' must be an action.params.<name> path", Decision.unitTagsError(j("{'amount':{'kind':'k'}}")));
        assertEquals("units['action.params.a'] must be an object", Decision.unitTagsError(j("{'action.params.a':3}")));
        assertEquals("unknown member 'units['action.params.a'].x'", Decision.unitTagsError(j("{'action.params.a':{'kind':'k','x':1}}")));
        assertEquals("missing member 'units['action.params.a'].kind'", Decision.unitTagsError(j("{'action.params.a':{}}")));
        Map<String, Object> many = new LinkedHashMap<>();
        for (int i = 0; i < 64; i++) many.put("action.params.p" + i, jm("{'kind':'k'}"));
        assertNull(Decision.unitTagsError(many));
        many.put("action.params.p64", jm("{'kind':'k'}"));
        assertEquals("units has more than 64 entries", Decision.unitTagsError(many));
    }

    @Test void unitConfusionAndMissingTagsHaveExactReasons() {
        String cents = "{'action.params.amount':{'kind':'money','currency':'USD','exponent':0}}";
        assertEquals("'action.params.amount' is declared as money/USD/e2 by the action schema but the policy term is tagged money/USD/e0 (unit confusion)", units(cents, SU).reason);
        String eur = "{'action.params.amount':{'kind':'money','currency':'EUR','exponent':2}}";
        assertFalse(units(eur, SU).ok);
        String noCcy = "{'action.params.amount':{'kind':'money','exponent':2}}";
        assertFalse(units(noCcy, SU).ok);
        assertEquals("'action.params.note' is declared as no unit by the action schema but the policy term is tagged money (unit confusion)",
            units("{'action.params.note':{'kind':'money'}}", SU).reason);
        assertTrue(units("{'action.params.other':{'kind':'money'}}", SU).ok, "a tag for an undeclared parameter is ignored");
        String terms = ",'predicates':[[{'verb':'refund','where':[{'field':'action.params.amount','op':'lte','value':1}]}]]";
        assertEquals("a policy term reads 'action.params.amount' (money/USD/e2) without a unit tag", units("{}", SU + terms).reason);
        assertTrue(units("{}", SU.replace("'verb':'refund'", "'verb':'other'") + terms).ok, "another verb's predicate is out of scope");
        assertTrue(units("{}", SU + ",'predicates':[[{'verb':['x','refund'],'where':[{'field':'action.params.note','op':'lte','value':1}]}]]").ok);
        assertFalse(units("{}", SU + ",'predicates':[[{'verb':['x','refund'],'where':[{'field':'action.params.amount','op':'lte','value':1}]}]]").ok);
        assertFalse(units("{}", SU + ",'predicates':[[{'verb':'*','where':[{'all_of':[{'ref':'action.params.amount'}]}]}]]").ok);
        assertEquals("the verb is missing", Decision.decideUnits(jm("{'units':{}}")).reason);
        assertEquals("the verb is missing", Decision.decideUnits(jm("{'units':{},'verb':''}")).reason);
        assertEquals("the schema does not declare verb 'refund'", Decision.decideUnits(jm("{'units':{},'verb':'refund'}")).reason);
        assertEquals("the schema units table must be an object", Decision.decideUnits(jm("{'units':{},'verb':'refund','schema_units':null,'verb_params':{}}")).reason);
        assertTrue(Decision.decideUnits(jm("{'units':{},'verb':'refund','verb_params':{}}")).ok, "absent schema units is empty");
        assertEquals("units must be an object", Decision.decideUnits(jm("{}")).reason);
    }

    // ---- escalation ----

    @Test void requestCapsReasonsAndTextsAreExact() {
        Map<String, Object> grant = EscalationTest.grant();
        Map<String, Object> p = jm("{'action':{'verb':'v','resource':5}}");
        List<String> rs = new ArrayList<>();
        for (int i = 0; i < 20; i++) rs.add("r" + i);
        rs.set(0, "x".repeat(600));
        Map<String, Object> q = Escalation.buildRequest(null, grant, p, 7L, rs, 1000L);
        assertEquals("", q.get("aud"));
        assertEquals("v", q.get("verb"));
        assertEquals("5", q.get("resource"));
        List<?> out = (List<?>) q.get("reasons");
        assertEquals(16, out.size());
        assertEquals(512, ((String) out.get(0)).length());
        assertEquals("r15", out.get(15));
        assertEquals("3601000", q.get("expires_at").toString());
        assertEquals(Escalation.historyHead(7L), q.get("history_head"));
        assertFalse(Escalation.historyHead(7L).equals(Escalation.historyHead(null)));
        assertFalse(Escalation.historyHead(0L).equals(Escalation.historyHead(null)));
        Map<String, Object> q2 = Escalation.buildRequest("aud", grant, jm("{}"), null, List.of(), 0L);
        assertEquals("undefined", q2.get("verb"));
        assertEquals("aud", q2.get("aud"));
    }

    static Escalation.Binding bind(Long last) {
        return new Escalation.Binding(Escalation.policyDigest(EscalationTest.grant()), Escalation.actionDigest(EscalationTest.pcactn()), Escalation.historyHead(last));
    }

    static Map<String, Object> over(String k, Object v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put(k, v);
        return m;
    }

    static Escalation.Result verify(Map<String, Object> a, long now) { return Escalation.verify(a, List.of(a.get("principal")), bind(null), now); }

    @Test void answerTimeAndLifetimeBoundaries() throws Exception {
        long iat = 1_000_000L;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("iat", IntentJs.ofLong(iat));
        m.put("expires_at", IntentJs.ofLong(iat + 86_400_000L));
        Map<String, Object> a = EscalationTest.answer(null, m);
        assertTrue(verify(a, iat).ok, "now == iat");
        assertTrue(verify(a, iat + 86_400_000L).ok, "now == expires_at");
        assertEquals("the answer is from the future", verify(a, iat - 1).reason);
        assertEquals("the answer has expired", verify(a, iat + 86_400_001L).reason);
        m.put("expires_at", IntentJs.ofLong(iat + 86_400_001L));
        assertEquals("malformed escalation answer: an answer lives at most 86400000 ms", verify(EscalationTest.answer(null, m), iat).reason);
        m.put("expires_at", IntentJs.ofLong(iat));
        assertEquals("malformed escalation answer: expires_at must be greater than iat", verify(EscalationTest.answer(null, m), iat).reason);
        m.put("expires_at", IntentJs.ofLong(iat + 1));
        assertTrue(verify(EscalationTest.answer(null, m), iat).ok, "one millisecond of life");
        assertEquals("the verifier clock is not a safe integer (fail closed)", verify(a, 9007199254740992L).reason);
        assertEquals("the verifier clock is not a safe integer (fail closed)", verify(a, -9007199254740992L).reason);
        m.put("iat", IntentJs.ofLong(-1));
        assertEquals("malformed escalation answer: iat and expires_at must be non-negative safe integers", verify(EscalationTest.answer(null, m), 0).reason);
        m.put("iat", "5");
        assertEquals("malformed escalation answer: iat and expires_at must be non-negative safe integers", verify(EscalationTest.answer(null, m), 0).reason);
    }

    @Test void answerShapeMessagesAreExact() throws Exception {
        assertEquals("not an object", Escalation.answerShapeError(null));
        assertEquals("not an object", Escalation.answerShapeError(List.of()));
        Map<String, Object> ok = EscalationTest.answer(null, null);
        assertNull(Escalation.answerShapeError(ok));
        Map<String, Object> x = new LinkedHashMap<>(ok);
        x.put("extra", "1");
        assertEquals("unknown member 'answer.extra'", Escalation.answerShapeError(x));
        x = new LinkedHashMap<>(ok);
        x.remove("nonce");
        assertEquals("missing member 'answer.nonce'", Escalation.answerShapeError(x));
        assertEquals("not a pca-escalation-answer v1", Escalation.answerShapeError(with(ok, "v", IntentJs.ofLong(2))));
        assertEquals("not a pca-escalation-answer v1", Escalation.answerShapeError(with(ok, "kind", "pca-escalation-request")));
        assertEquals("principal must be canonical base64url (32 bytes)", Escalation.answerShapeError(with(ok, "principal", "AAAA")));
        for (String k : new String[] {"policy_digest", "action_digest", "history_head"})
            assertEquals(k + " must be canonical base64url (32 bytes)", Escalation.answerShapeError(with(ok, k, "AAAA")));
        assertEquals("decision must be 'allow' or 'deny'", Escalation.answerShapeError(with(ok, "decision", "maybe")));
        assertEquals("nonce must be canonical base64url of at least 16 bytes", Escalation.answerShapeError(with(ok, "nonce", Pca.b64(new byte[15]))));
        assertNull(Escalation.answerShapeError(with(ok, "nonce", Pca.b64(new byte[16]))));
        assertEquals("nonce must be canonical base64url of at least 16 bytes", Escalation.answerShapeError(with(ok, "nonce", 5L)));
        assertEquals("sig must be a string", Escalation.answerShapeError(with(ok, "sig", 5L)));
        assertEquals("alg must be a string", Escalation.answerShapeError(with(ok, "alg", 5L)));
        assertEquals("pq_sig must be a string", Escalation.answerShapeError(with(with(ok, "alg", "ml-dsa-65"), "pq_sig", 5L)));
        assertEquals("an ed25519 artifact must not carry pq_pk / pq_sig", Escalation.answerShapeError(with(ok, "pq_pk", "x")));
    }

    static Map<String, Object> with(Map<String, Object> m, String k, Object v) {
        Map<String, Object> c = new LinkedHashMap<>(m);
        c.put(k, v);
        return c;
    }

    @Test void aSignatureOverAnotherBodyOrKeyIsRefused() throws Exception {
        Map<String, Object> a = EscalationTest.answer(null, null);
        long now = AuthorizeFixtures.now();
        assertTrue(Escalation.verify(a, List.of(EscalationTest.pub()), bind(null), now).ok);
        assertEquals("escalation answer signature invalid", Escalation.verify(with(a, "decision", "deny"), List.of(EscalationTest.pub()), bind(null), now).reason);
        assertEquals("escalation answer signature invalid", Escalation.verify(with(a, "nonce", Pca.b64(new byte[20])), List.of(EscalationTest.pub()), bind(null), now).reason);
        Map<String, Object> pinNoPq = new LinkedHashMap<>();
        pinNoPq.put("pk", EscalationTest.pub());
        assertTrue(Escalation.verify(a, List.of(pinNoPq), bind(null), now).ok);
        assertEquals("the answering principal is not pinned by this verifier", Escalation.verify(a, List.of(EscalationTest.ZERO, 5L, "x"), bind(null), now).reason);
        assertEquals("no principal is pinned for escalation answers", Escalation.verify(a, List.of(), bind(null), now).reason);
        assertEquals("no principal is pinned for escalation answers", Escalation.verify(a, null, bind(null), now).reason);
        assertEquals("the answer is bound to another policy", Escalation.verify(a, List.of(EscalationTest.pub()),
            new Escalation.Binding(EscalationTest.ZERO, bind(null).actionDigest, bind(null).historyHead), now).reason);
        assertEquals("the answer is bound to another action", Escalation.verify(a, List.of(EscalationTest.pub()),
            new Escalation.Binding(bind(null).policyDigest, EscalationTest.ZERO, bind(null).historyHead), now).reason);
        assertEquals("the answer is bound to another state of the history", Escalation.verify(a, List.of(EscalationTest.pub()), bind(1L), now).reason);
    }

    @Test void aPostQuantumSuiteNeedsAPinnedPqKey() throws Exception {
        Map<String, Object> a = EscalationTest.answer(null, null);
        Map<String, Object> pq = with(with(a, "alg", "ml-dsa-65"), "pq_pk", Pca.b64(new byte[1952]));
        String shape = Escalation.answerShapeError(pq);
        // a suite this SDK implements passes the shape check; the Ed25519 signature no longer covers the body, so it never verifies
        if (shape == null) assertFalse(Escalation.verify(pq, List.of(EscalationTest.pub()), bind(null), AuthorizeFixtures.now()).ok);
        else assertTrue(shape.startsWith("unsupported_suite"), shape);
        assertTrue(Escalation.answerShapeError(with(a, "alg", "no-such-suite")).startsWith("unsupported_suite"));
    }
}
