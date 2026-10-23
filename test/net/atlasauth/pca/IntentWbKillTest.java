package net.atlasauth.pca;

import static net.atlasauth.pca.IntentV2KillTest.b64seed;
import static net.atlasauth.pca.IntentV2KillTest.list;
import static net.atlasauth.pca.IntentV2KillTest.map;
import static net.atlasauth.pca.IntentV2KillTest.pub;
import static net.atlasauth.pca.IntentV2KillTest.sign;
import static org.junit.jupiter.api.Assertions.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Mutation kills for the W-B rules 16 (facts, relational, offer sets), 17 (provenance, label receipts, flows), 18 (classifiers) and the unit. */
public class IntentWbKillTest {
    static final long NOW = 1_800_000_000_000L;
    static final String AUD = "skyair.example";
    static final String SESSION = b64seed("wb/session");

    static Map<String, Object> signed(String domain, Map<String, Object> body, String key) {
        Map<String, Object> a = new LinkedHashMap<>(body);
        a.put("sig", sign(key, IntentJs.message(domain, body)));
        return a;
    }
    static Map<String, Object> fact(String name, String subject, Object value, long tObs, String oracle, String key) {
        return signed(OracleFacts.FACT_DOMAIN, map("v", 1L, "kind", "pca-fact", "name", name, "subject", subject, "value", value, "t_obs", tObs, "oracle", oracle), key);
    }
    static Map<String, Object> world(int min, int faulty, long fresh) {
        return map("name", "fx", "subject_path", "action.resource", "freshness_ms", fresh, "min_oracles", (long) min, "max_faulty", (long) faulty,
            "oracles", list(map("kid", "o1", "pk", pub("wb/o1")), map("kid", "o2", "pk", pub("wb/o2")), map("kid", "o3", "pk", pub("wb/o3"))));
    }
    static Map<String, Object> action(Object... params) {
        return map("verb", "air.book", "resource", "EURUSD", "params", map(params));
    }
    static OracleFacts.WorldResult decideWorld(List<Object> facts, Map<String, Object> policy, Object now, Map<String, Object> action) {
        List<Object> committed = new java.util.ArrayList<>();
        for (Object f : facts) committed.add(OracleFacts.factRef(IntentJs.obj(IntentJs.normalize(f))));
        return OracleFacts.decideIntentWorld(map("now", now, "aud", AUD, "session", SESSION, "action", action, "committed", map("facts", committed), "facts", facts, "policy", policy));
    }

    @Test void worldMedianFreshnessAndClock() {
        Map<String, Object> pol = map("worlds", list(world(3, 1, 60_000L)));
        List<Object> f3 = list(fact("fx", "EURUSD", 7L, NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2"), fact("fx", "EURUSD", 9L, NOW, "o3", "wb/o3"));
        OracleFacts.WorldResult r = decideWorld(f3, pol, NOW, action());
        assertTrue(r.ok, r.reason);
        assertEquals("7", r.world.get("fx").toString());
        assertTrue(r.singleSource.isEmpty());
        // lower median of an even count: index floor((n-1)/2)
        Map<String, Object> pol2 = map("worlds", list(world(2, 0, 60_000L)));
        OracleFacts.WorldResult even = decideWorld(list(fact("fx", "EURUSD", 9L, NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action());
        assertEquals("1", even.world.get("fx").toString());
        // freshness: now - t_obs <= freshness (inclusive); t_obs <= now + skew (inclusive, default 60 s)
        assertTrue(decideWorld(list(fact("fx", "EURUSD", 1L, NOW - 60_000, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW + 60_000, "o2", "wb/o2")), pol2, NOW, action()).ok);
        assertFalse(decideWorld(list(fact("fx", "EURUSD", 1L, NOW - 60_001, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok);
        assertFalse(decideWorld(list(fact("fx", "EURUSD", 1L, NOW + 60_001, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok);
        // CLOCK: a now that is not a safe integer makes every fact stale
        for (Object badNow : new Object[] {String.valueOf(NOW), new Json.Num("1800000000000.5"), null})
            assertFalse(decideWorld(list(fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, badNow, action()).ok, String.valueOf(badNow));
        // strings must agree; a mix fails
        assertEquals("up", decideWorld(list(fact("fx", "EURUSD", "up", NOW, "o1", "wb/o1"), fact("fx", "EURUSD", "up", NOW, "o2", "wb/o2")), pol2, NOW, action()).world.get("fx"));
        assertFalse(decideWorld(list(fact("fx", "EURUSD", "up", NOW, "o1", "wb/o1"), fact("fx", "EURUSD", "dn", NOW, "o2", "wb/o2")), pol2, NOW, action()).ok);
        assertFalse(decideWorld(list(fact("fx", "EURUSD", "up", NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok);
        // single source
        assertEquals(List.of("fx"), decideWorld(list(fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1")), map("worlds", list(world(1, 0, 60_000L))), NOW, action()).singleSource);
    }

    @Test void worldRefusals() {
        Map<String, Object> pol2 = map("worlds", list(world(2, 0, 60_000L)));
        Map<String, Object> f1 = fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1");
        assertFalse(decideWorld(list(f1, fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1x")), pol2, NOW, action()).ok); // wrong key for o1
        assertFalse(decideWorld(list(f1, fact("fx", "EURUSD", 1L, NOW, "o9", "wb/o2")), pol2, NOW, action()).ok); // unpinned kid
        assertFalse(decideWorld(list(f1, fact("fx", "GBPUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok); // subject
        assertFalse(decideWorld(list(f1, fact("fx", "EURUSD", 2L, NOW + 1, "o1", "wb/o1")), pol2, NOW, action()).ok); // duplicate oracle
        assertFalse(decideWorld(list(f1, fact("gx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok); // undeclared world
        // an uncommitted supplied fact is ignored; a committed one that is not supplied fails
        Map<String, Object> in = map("now", NOW, "aud", AUD, "session", SESSION, "action", action(), "committed", map("facts", list(b64seed("wb/none"))), "facts", list(f1), "policy", map());
        assertFalse(OracleFacts.decideIntentWorld(in).ok);
        Map<String, Object> in2 = map("now", NOW, "aud", AUD, "session", SESSION, "action", action(), "committed", map(), "facts", list(f1), "policy", map());
        assertTrue(OracleFacts.decideIntentWorld(in2).ok);
        // policy: min_oracles >= 2f+1; at most 16 worlds; skew a safe integer >= 0
        assertFalse(decideWorld(list(), map("worlds", list(world(2, 1, 60_000L))), NOW, action()).ok);
        assertFalse(decideWorld(list(), map("skew_ms", -1L), NOW, action()).ok);
        assertTrue(decideWorld(list(), map("skew_ms", 0L), NOW, action()).ok);
    }

    @Test void relational() {
        Map<String, Object> pol = map("relational", list(map("name", "d", "fn", "sub", "a", "action.params.a", "b", "action.params.b"),
            map("name", "r", "fn", "ratio_ppm", "a", "env.world.d", "b", "action.params.b")));
        OracleFacts.WorldResult ok = decideWorld(list(), pol, NOW, action("a", 3L, "b", 2L));
        assertTrue(ok.ok, ok.reason);
        assertEquals("1", ok.world.get("d").toString());
        assertEquals("500000", ok.world.get("r").toString());
        assertEquals("-1", decideWorld(list(), map("relational", list(map("name", "d", "fn", "sub", "a", "action.params.a", "b", "action.params.b"))), NOW, action("a", 1L, "b", 2L)).world.get("d").toString());
        assertFalse(decideWorld(list(), pol, NOW, action("a", 3L, "b", 0L)).ok); // b > 0
        assertFalse(decideWorld(list(), pol, NOW, action("a", 1L, "b", 2L)).ok); // ratio a >= 0 (d = -1)
        assertFalse(decideWorld(list(), pol, NOW, action("a", 9007199254740991L, "b", -9007199254740991L)).ok); // overflow
        // the clock does not matter for relational dimensions
        assertTrue(decideWorld(list(), pol, "x", action("a", 3L, "b", 2L)).ok);
        // an operand must name an EARLIER dimension
        assertFalse(decideWorld(list(), map("relational", list(map("name", "d", "fn", "sub", "a", "env.world.d", "b", "action.params.b"))), NOW, action("b", 1L)).ok);
        // own-member keys: a dimension named like a built-in member is an ordinary key
        assertEquals("1", decideWorld(list(), map("relational", list(map("name", "constructor", "fn", "sub", "a", "action.params.a", "b", "action.params.b"))), NOW, action("a", 3L, "b", 2L)).world.get("constructor").toString());
    }

    static Map<String, Object> offerSet(Object... over) {
        Map<String, Object> body = map("v", 1L, "kind", "pca-offer-set", "site", AUD, "session", SESSION, "query", map("from", "SFO"), "rank", "price_asc", "complete", true,
            "offers", list(map("offer_id", "A", "price", 100L, "cabin", "eco"), map("offer_id", "B", "price", 150L, "cabin", "eco"), map("offer_id", "C", "price", 90L, "cabin", "biz")),
            "issued_at", NOW - 1_000L, "kid", "s1");
        for (int i = 0; i < over.length; i += 2) body.put((String) over[i], over[i + 1]);
        return signed(OracleFacts.OFFER_SET_DOMAIN, body, "wb/site");
    }
    static Map<String, Object> offersPolicy(long maxAge) {
        return map("offers", map("name", "excess", "site_keys", list(map("kid", "s1", "pk", pub("wb/site"))), "max_age_ms", maxAge, "offer_param", "action.params.offer_id",
            "filter", map("query", map("from", "SFO"), "offer", map("cabin", "eco"))));
    }
    static OracleFacts.WorldResult decideOffers(Map<String, Object> os, Map<String, Object> pol, Object now, String chosen) {
        return OracleFacts.decideIntentWorld(map("now", now, "aud", AUD, "session", SESSION, "action", action("offer_id", chosen),
            "committed", map("offer_set", OracleFacts.offerSetRef(IntentJs.obj(IntentJs.normalize(os)))), "offer_set", os, "policy", pol));
    }

    @Test void offerSets() {
        OracleFacts.WorldResult ok = decideOffers(offerSet(), offersPolicy(60_000L), NOW, "B");
        assertTrue(ok.ok, ok.reason);
        assertEquals("50", ok.world.get("excess").toString()); // C is biz: filtered out of the minimum
        assertEquals("0", decideOffers(offerSet(), offersPolicy(60_000L), NOW, "A").world.get("excess").toString());
        assertFalse(decideOffers(offerSet(), offersPolicy(60_000L), NOW, "C").ok); // chosen offer filtered
        assertFalse(decideOffers(offerSet(), offersPolicy(60_000L), NOW, "Z").ok);
        assertTrue(decideOffers(offerSet(), offersPolicy(1_000L), NOW, "A").ok);  // age inclusive
        assertFalse(decideOffers(offerSet(), offersPolicy(999L), NOW, "A").ok);
        assertFalse(decideOffers(offerSet(), offersPolicy(60_000L), String.valueOf(NOW), "A").ok); // no usable clock
        assertFalse(decideOffers(offerSet("complete", false), offersPolicy(60_000L), NOW, "A").ok);
        assertFalse(decideOffers(offerSet("site", "other.example"), offersPolicy(60_000L), NOW, "A").ok);
        assertFalse(decideOffers(offerSet("query", map("from", "SFO", "to", "JFK")), offersPolicy(60_000L), NOW, "A").ok); // narrowed
        assertTrue(decideOffers(offerSet("query", map()), offersPolicy(60_000L), NOW, "A").ok); // broader query covers
        assertFalse(decideOffers(offerSet("issued_at", NOW + 60_001L), offersPolicy(120_000L), NOW, "A").ok);
        assertTrue(decideOffers(offerSet("issued_at", NOW + 60_000L), offersPolicy(120_000L), NOW, "A").ok);
        // typed scalar equality: 2 != "2"
        assertFalse(OracleFacts.offerMatches(map("x", 2L), map("x", "2")));
        assertTrue(OracleFacts.offerMatches(map("x", 2L), map("x", new Json.Num("2"))));
    }

    // ---- rule 17 ----
    static Map<String, Object> labels(String site, String kid, String key, Map<String, Object> fields) {
        return signed(ParamProvenance.LABELS_DOMAIN, map("v", 1L, "kind", "pca-labels", "site", site, "session", SESSION, "response_digest", b64seed("wb/resp"),
            "fields", fields, "issued_at", NOW, "kid", kid), key);
    }
    static ParamProvenance.ProvResult prov(Map<String, Object> params, Map<String, Object> prov, List<Object> receipts, Map<String, Object> policy) {
        List<Object> committed = new java.util.ArrayList<>();
        for (Object r : receipts) committed.add(ParamProvenance.labelsRef(IntentJs.obj(IntentJs.normalize(r))));
        return ParamProvenance.decide(map("aud", AUD, "session", SESSION, "action", map("params", params), "prov", prov, "committed_labels", committed, "labels", receipts, "policy", policy));
    }

    @Test void provenance() {
        Map<String, Object> reg = map("vouched", "trusted", "fp", "first_party", "web", "web");
        Map<String, Object> pol = map("params", map("action.params.offer_id", "material", "action.params.total", "critical"), "registry", reg);
        ParamProvenance.ProvResult pass = prov(map("offer_id", "A", "total", 5L), map("action.params.offer_id", list("fp"), "action.params.total", list("vouched")), list(), pol);
        assertEquals("pass", pass.outcome, pass.reason);
        assertEquals("first_party", pass.labels.get("action.params.offer_id"));
        // tainted material -> question (tap); tainted critical -> question_typed by default
        ParamProvenance.ProvResult q = prov(map("offer_id", "A", "total", 5L), map("action.params.offer_id", list("web"), "action.params.total", list("vouched")), list(), pol);
        assertEquals("question", q.outcome);
        assertEquals("tap", q.friction);
        ParamProvenance.ProvResult qt = prov(map("offer_id", "A", "total", 5L), map("action.params.offer_id", list("fp"), "action.params.total", list("web")), list(), pol);
        assertEquals("typed", qt.friction);
        // undeclared parameter in policy.params that the action carries: agent
        ParamProvenance.ProvResult undeclared = prov(map("offer_id", "A", "total", 5L), map("action.params.offer_id", list("fp")), list(), pol);
        assertEquals("agent", undeclared.labels.get("action.params.total"));
        // join is the highest rank; an unknown ref (even a built-in name) is agent
        assertEquals("web", prov(map("offer_id", "A"), map("action.params.offer_id", list("fp", "web")), list(), map("params", map(), "registry", reg)).labels.get("action.params.offer_id"));
        assertEquals("agent", prov(map("offer_id", "A"), map("action.params.offer_id", list("constructor")), list(), map("params", map(), "registry", reg)).labels.get("action.params.offer_id"));
        // critical_max and modes
        Map<String, Object> strict = new LinkedHashMap<>(pol); strict.put("critical_max", "first_party");
        assertEquals("deny", prov(map("offer_id", "A", "total", 5L), map("action.params.offer_id", list("fp"), "action.params.total", list("web")), list(), strict).outcome);
        Map<String, Object> allow = new LinkedHashMap<>(pol); allow.put("material_tainted", "allow");
        assertEquals("pass", prov(map("offer_id", "A", "total", 5L), map("action.params.offer_id", list("web"), "action.params.total", list("vouched")), list(), allow).outcome);
        Map<String, Object> bad = new LinkedHashMap<>(pol); bad.put("critical_tainted", "allow");
        assertEquals("deny", prov(map("offer_id", "A"), map(), list(), bad).outcome);
        // prov names an absent parameter; prototype-named prov keys are refused
        assertEquals("deny", prov(map(), map("action.params.offer_id", list("fp")), list(), pol).outcome);
        assertEquals("deny", prov(map("constructor", "x"), map("action.params.constructor", list("fp")), list(), map("params", map())).outcome);
    }

    @Test void labelReceiptsAndFlows() {
        Map<String, Object> keys = map("params", map("action.params.offer_id", "material"), "label_keys", list(map("site", AUD, "kid", "k1", "pk", pub("wb/site")),
            map("site", "gov.example", "kid", "g1", "pk", pub("wb/gov"))));
        Map<String, Object> mine = labels(AUD, "k1", "wb/site", map("offer", map("class", "pii.contact", "value_digest", IntentJs.hashCanonical("A"))));
        String ref = "pca-labels:" + ParamProvenance.labelsRef(IntentJs.obj(IntentJs.normalize(mine))) + "#offer";
        ParamProvenance.ProvResult fp = prov(map("offer_id", "A"), map("action.params.offer_id", list(ref)), list(mine), keys);
        assertEquals("pass", fp.outcome, fp.reason);
        assertEquals("first_party", fp.labels.get("action.params.offer_id"));
        assertEquals(List.of("pii.contact"), fp.classes.get("action.params.offer_id"));
        // value mismatch -> agent (a material question); a foreign site -> tool, and the flow must allow it
        assertEquals("question", prov(map("offer_id", "B"), map("action.params.offer_id", list(ref)), list(mine), keys).outcome);
        Map<String, Object> gov = labels("gov.example", "g1", "wb/gov", map("offer", map("class", "pii.contact", "value_digest", IntentJs.hashCanonical("A"))));
        String gref = "pca-labels:" + ParamProvenance.labelsRef(IntentJs.obj(IntentJs.normalize(gov))) + "#offer";
        assertEquals("deny", prov(map("offer_id", "A"), map("action.params.offer_id", list(gref)), list(gov), keys).outcome); // no flow rule
        Map<String, Object> flows = new LinkedHashMap<>(keys); flows.put("flows", map("pii.*", list(AUD)));
        assertEquals("question", prov(map("offer_id", "A"), map("action.params.offer_id", list(gref)), list(gov), flows).outcome); // tool: tainted material
        Map<String, Object> narrower = new LinkedHashMap<>(keys); narrower.put("flows", map("pii.*", list(AUD), "pii.contact", list("x.example")));
        assertEquals("deny", prov(map("offer_id", "A"), map("action.params.offer_id", list(gref)), list(gov), narrower).outcome); // most specific wins
        // a missing field, an uncommitted receipt, another session
        assertEquals("deny", prov(map("offer_id", "A"), map("action.params.offer_id", list(ref.replace("#offer", "#nope"))), list(mine), keys).outcome);
        assertEquals("deny", prov(map("offer_id", "A"), map("action.params.offer_id", list(ref.replace("#offer", "#"))), list(mine), keys).outcome);
        assertEquals("deny", ParamProvenance.decide(map("aud", AUD, "session", SESSION, "action", map("params", map("offer_id", "A")),
            "prov", map("action.params.offer_id", list(ref)), "committed_labels", list(), "labels", list(mine), "policy", keys)).outcome);
        assertEquals("deny", ParamProvenance.decide(map("aud", AUD, "session", b64seed("wb/other"), "action", map("params", map("offer_id", "A")),
            "prov", map("action.params.offer_id", list(ref)), "committed_labels", list(ParamProvenance.labelsRef(IntentJs.obj(IntentJs.normalize(mine)))), "labels", list(mine), "policy", keys)).outcome);
        // flow rule resolution
        Map<String, Object> rules = map("pii.*", list("a"), "pii.contact.*", list("b"), "*", list("c"));
        assertEquals("pii.contact.*", ParamProvenance.flowRuleFor(rules, "pii.contact.email"));
        assertEquals("pii.*", ParamProvenance.flowRuleFor(rules, "pii.contact"));
        assertEquals("*", ParamProvenance.flowRuleFor(rules, "piix"));
        assertTrue(ParamProvenance.flowAllowed(map(), "x", "o", "o"));
        assertTrue(ParamProvenance.flowAllowed(map(), "public", "o", "a"));
        assertFalse(ParamProvenance.flowAllowed(map(), "x", "o", "a"));
    }

    // ---- rule 18 ----
    static Map<String, Object> verdict(String classifier, String label, String measurement, String key, Object content) {
        return signed(IntentClassifier.INTENT_CLASSIFIER_DOMAIN, map("v", 1L, "kind", "pca-intent-classification", "classifier", classifier, "session", SESSION,
            "content_digest", IntentJs.hashCanonical(content), "label", label, "measurement", measurement, "judge", pub(key)), key);
    }
    static IntentClassifier.ClassResult classify(List<Object> verdicts, long k, Object measurements) {
        Map<String, Object> c = map("id", "tone", "param", "action.params.body", "labels", list("apologetic", "neutral"), "keys", list(pub("wb/j1"), pub("wb/j2"), pub("wb/j3")), "k", k);
        if (measurements != null) c.put("measurements", measurements);
        List<Object> committed = new java.util.ArrayList<>();
        for (Object v : verdicts) committed.add(IntentClassifier.verdictRef(IntentJs.obj(IntentJs.normalize(v))));
        return IntentClassifier.decide(map("session", SESSION, "action", map("params", map("body", "sorry")), "committed", committed, "verdicts", verdicts, "policy", map("classifiers", list(c))));
    }

    @Test void classifiers() {
        Map<String, Object> a1 = verdict("tone", "apologetic", "m1", "wb/j1", "sorry"), a2 = verdict("tone", "apologetic", "m1", "wb/j2", "sorry"),
            n3 = verdict("tone", "neutral", "m1", "wb/j3", "sorry");
        IntentClassifier.ClassResult r = classify(list(a1, a2, n3), 2, null);
        assertTrue(r.ok, r.reason);
        assertEquals("apologetic", r.classes.get("tone"));
        assertFalse(classify(list(a1, n3), 2, null).ok);                 // no quorum
        assertFalse(classify(list(a1, n3), 1, null).ok);                 // ambiguous
        assertTrue(classify(list(a1), 1, null).ok);
        assertFalse(classify(list(a1), 4, null).ok);                     // k > |keys|: misconfigured
        assertFalse(classify(list(a1), 0, null).ok);
        assertFalse(classify(list(a1, verdict("tone", "apologetic", "m1", "wb/j1", "sorry")), 1, null).ok); // identical verdict: a duplicate committed digest
        assertFalse(classify(list(a1, verdict("tone", "neutral", "m1", "wb/j1", "sorry")), 1, null).ok); // one judge twice
        assertFalse(classify(list(verdict("tone", "apologetic", "m1", "wb/stranger", "sorry")), 1, null).ok); // not allowlisted
        assertFalse(classify(list(verdict("tone", "apologetic", "m1", "wb/j1", "other")), 1, null).ok);       // other content
        assertFalse(classify(list(verdict("tone", "angry", "m1", "wb/j1", "sorry")), 1, null).ok);            // label not in set
        assertTrue(classify(list(a1), 1, list("m1")).ok);
        assertFalse(classify(list(a1), 1, list("m2")).ok);                // measurement not pinned
        assertFalse(classify(list(a1), 1, "m1").ok);                      // measurements must be a list
        // labels named like built-in members are ordinary labels
        Map<String, Object> c = map("id", "tone", "param", "action.params.body", "labels", list("constructor", "toString"), "keys", list(pub("wb/j1")), "k", 1L);
        Map<String, Object> v = verdict("tone", "constructor", "m1", "wb/j1", "sorry");
        IntentClassifier.ClassResult proto = IntentClassifier.decide(map("session", SESSION, "action", map("params", map("body", "sorry")),
            "committed", list(IntentClassifier.verdictRef(IntentJs.obj(IntentJs.normalize(v)))), "verdicts", list(v), "policy", map("classifiers", list(c))));
        assertTrue(proto.ok, proto.reason);
        assertEquals("constructor", proto.classes.get("tone"));
    }

    // ---- the unit and activity ----
    @Test void activityIsStrictlyTyped() {
        assertArrayEquals(new boolean[] {false, false, false}, IntentWB.active(map("intent_session", map(), "policy", map())));
        assertArrayEquals(new boolean[] {true, true, true}, IntentWB.active(map("intent_session", map("facts", list(SESSION), "prov", map(), "classes", list(SESSION)), "policy", map())));
        assertArrayEquals(new boolean[] {false, true, false}, IntentWB.active(map("intent_session", map("facts", list(), "prov", null, "classes", list()), "policy", map())));
        assertArrayEquals(new boolean[] {true, false, false}, IntentWB.active(map("intent_session", map("offer_set", SESSION), "policy", map())));
        assertArrayEquals(new boolean[] {false, false, false}, IntentWB.active(map("intent_session", map("offer_set", 1L, "labels", list()), "policy", map())));
        assertArrayEquals(new boolean[] {false, false, false}, IntentWB.active(map("intent_session", map(), "policy",
            map("world", map("worlds", map("length", 1L), "offers", list()), "provenance", list(), "classifiers", map("length", 1L)))));
        assertArrayEquals(new boolean[] {true, true, true}, IntentWB.active(map("intent_session", map(), "policy",
            map("world", map("offers", map()), "provenance", map(), "classifiers", list(map())))));
    }

    @Test void unitOrder() {
        // facts fails -> provenance and classes are not reported
        IntentWB.Result r = IntentWB.decide(map("now", NOW, "aud", AUD, "session", SESSION, "action", action(), "intent_session", map(),
            "policy", map("world", map("worlds", list(map())), "provenance", map("params", map()), "classifiers", list(map()))));
        assertEquals("deny", r.outcome);
        assertEquals(List.of("facts"), new java.util.ArrayList<>(r.checks.keySet()));
        // a provenance question continues to classes
        Map<String, Object> pol = map("provenance", map("params", map("action.params.x", "material")), "classifiers", list(map()));
        IntentWB.Result q = IntentWB.decide(map("now", NOW, "aud", AUD, "session", SESSION, "action", action("x", "1"), "intent_session", map(), "policy", pol));
        assertEquals(List.of("provenance", "classes"), new java.util.ArrayList<>(q.checks.keySet()));
        assertEquals("question", q.checks.get("provenance"));
        assertEquals("fail", q.checks.get("classes"));
    }
}
