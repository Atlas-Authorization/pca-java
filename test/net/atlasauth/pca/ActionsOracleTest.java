package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * K042-style differential kills for {@link Actions}: the trait closure/floor against an independent eight-round one-step
 * oracle written from the spec (not from the production code), exact FloorDecision semantics on the full small grid,
 * digest invariance under authoring noise, and the exact rule 22 refusals at every boundary (one below the floor fails,
 * exactly the floor passes). Boundary targets: esc &gt; vs &gt;=, subset direction, implies depth 8 vs 9, rev rank, ppm.
 */
public class ActionsOracleTest {
    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> M(Object o) { return ActionVectorsTest.M(o); }

    // ---- oracle: eight rounds of one-step implication over the registry's implies lists; join over floor maps ---------------

    static List<String> oracleClosure(Actions.Registry reg, List<String> ids) {
        TreeSet<String> cur = new TreeSet<>(ids);
        for (int round = 0; round < 8; round++) {
            TreeSet<String> next = new TreeSet<>(cur);
            for (String t : cur) next.addAll(reg.traits.get(t).implies);
            cur = next;
        }
        return new ArrayList<>(cur);
    }

    static int rank(String r) { return r.equals("reversible") ? 0 : r.equals("rate_limited") ? 1 : 2; }

    static Map<String, Object> oracleFloor(Actions.Registry reg, List<String> cl) {
        long risk = 0, blast = 0, esc = 0; String rev = "reversible";
        TreeSet<String> cav = new TreeSet<>(), ctx = new TreeSet<>(), pr = new TreeSet<>();
        for (String t : cl) {
            Map<String, Object> f = reg.traits.get(t).floor.toMap();
            risk = Math.max(risk, IntentJs.lng(f.get("risk"))); blast = Math.max(blast, IntentJs.lng(f.get("blast_ppm"))); esc = Math.max(esc, IntentJs.lng(f.get("esc")));
            if (rank((String) f.get("rev")) > rank(rev)) rev = (String) f.get("rev");
            for (Object o : (List<?>) f.get("caveats")) cav.add((String) o);
            for (Object o : (List<?>) f.get("context")) ctx.add((String) o);
            for (Object o : (List<?>) f.get("prules")) pr.add((String) o);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("risk", n(risk)); m.put("rev", rev); m.put("blast_ppm", n(blast)); m.put("esc", n(esc));
        m.put("caveats", new ArrayList<Object>(cav)); m.put("context", new ArrayList<Object>(ctx)); m.put("prules", new ArrayList<Object>(pr));
        return m;
    }

    static Map<String, Object> custom(String id, List<String> implies, Map<String, Object> floor) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id); m.put("implies", new ArrayList<Object>(implies)); m.put("floor", floor); m.put("card_phrase", id);
        return m;
    }

    @Test
    void closureAndFloorMatchTheOracleOnRandomSets() {
        Random r = new Random(0xac7101L);
        List<String> core = new ArrayList<>(Actions.CORE_REGISTRY.traits.keySet());
        // a custom chain c0 -> c1 -> c2 -> pca.money_moving, each floor at least the implied floor (esc non-increasing along the chain)
        Map<String, Object> mm = Actions.CORE_REGISTRY.traits.get("pca.money_moving").floor.toMap();
        List<Object> cs = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            Map<String, Object> f = new LinkedHashMap<>(mm); f.put("esc", n(Math.min(3, 4 - i)));
            cs.add(custom("acme.c" + i, List.of(i < 2 ? "acme.c" + (i + 1) : "pca.money_moving"), f));
        }
        Actions.Registry ext = Actions.extendRegistry(Actions.CORE_REGISTRY, cs);
        for (Actions.Registry reg : new Actions.Registry[] {Actions.CORE_REGISTRY, ext}) {
            List<String> all = new ArrayList<>(reg.traits.keySet());
            for (int i = 0; i < 400; i++) {
                List<String> ids = new ArrayList<>();
                int k = r.nextInt(5);
                for (int j = 0; j < k; j++) ids.add(all.get(r.nextInt(all.size())));
                List<String> want = oracleClosure(reg, ids);
                assertEquals(want, Actions.closure(reg, new ArrayList<Object>(ids)));
                assertEquals(Json.canonicalize(oracleFloor(reg, want)), Json.canonicalize(IntentJs.normalize(Actions.floorOf(reg, new ArrayList<Object>(ids)).toMap())));
            }
        }
        assertTrue(core.size() == 22);
    }

    @Test
    void impliesDepthEightIsAcceptedAndNineRefused() {
        for (int depth = 8; depth <= 9; depth++) {
            List<Object> cs = new ArrayList<>();
            for (int i = 0; i < depth; i++) cs.add(custom("acme.c" + i, i < depth - 1 ? List.of("acme.c" + (i + 1)) : List.of(), Actions.Profile.BOTTOM.toMap()));
            boolean ok;
            try { Actions.extendRegistry(Actions.CORE_REGISTRY, cs); ok = true; } catch (Actions.ActionKitError e) { ok = false; assertEquals("bad_registry", e.code); }
            assertEquals(depth == 8, ok);
        }
    }

    @Test
    void customTraitMayNotWeakenOrReuseCoreNames() {
        Map<String, Object> weak = Actions.Profile.BOTTOM.toMap();
        try { Actions.extendRegistry(Actions.CORE_REGISTRY, new ArrayList<Object>(List.of(custom("acme.weak", List.of("pca.money_moving"), weak)))); fail("weakening accepted"); } catch (Actions.ActionKitError e) { assertEquals("bad_registry", e.code); }
        try { Actions.extendRegistry(Actions.CORE_REGISTRY, new ArrayList<Object>(List.of(custom("pca.fresh", List.of(), weak)))); fail("pca. accepted"); } catch (Actions.ActionKitError e) { assertEquals("bad_registry", e.code); }
        try { Actions.closure(Actions.CORE_REGISTRY, new ArrayList<Object>(List.of("pca.nope"))); fail("unknown accepted"); } catch (Actions.ActionKitError e) { assertEquals("unknown_trait", e.code); }
    }

    // ---- FloorDecision, exact on the whole small grid ------------------------------------------------------------------------

    static Map<String, Object> grant(List<String> cav, int max, int pre) {
        Map<String, Object> g = new LinkedHashMap<>();
        g.put("caveats", new ArrayList<Object>(cav)); g.put("max_esc", n(max)); g.put("preauth_esc", n(pre));
        return g;
    }
    static Map<String, Object> call(List<String> ctx) { Map<String, Object> c = new LinkedHashMap<>(); c.put("context", new ArrayList<Object>(ctx)); return c; }
    static Actions.Profile prof(int esc, List<String> cav, List<String> ctx) {
        Map<String, Object> m = Actions.Profile.BOTTOM.toMap();
        m.put("esc", n(esc)); m.put("caveats", new ArrayList<Object>(cav)); m.put("context", new ArrayList<Object>(ctx));
        return Actions.Profile.fromMap(m);
    }

    @Test
    void floorDecisionIsExactOnTheGridAndAntitone() {
        List<List<String>> sets = List.of(List.of(), List.of("amount_cap"), List.of("amount_cap", "window"));
        String[] order = {"deny", "escalate", "allow"};
        for (int esc = 0; esc <= 3; esc++) for (int max = 0; max <= 3; max++) for (int pre = 0; pre <= 3; pre++)
            for (List<String> need : sets) for (List<String> have : sets) for (List<String> ctxNeed : sets.subList(0, 2)) for (List<String> ctxHave : sets.subList(0, 2)) {
                List<String> needCtx = ctxNeed.isEmpty() ? List.of() : List.of("idempotency"), haveCtx = ctxHave.isEmpty() ? List.of() : List.of("idempotency");
                String want = esc > max ? "deny" : (!have.containsAll(need) || !haveCtx.containsAll(needCtx) || esc > pre) ? "escalate" : "allow";
                assertEquals(want, Actions.floorDecision(grant(have, max, pre), call(haveCtx), prof(esc, need, needCtx)));
                // antitone: raising esc or adding a required caveat never raises the decision
                if (esc < 3) assertTrue(java.util.Arrays.asList(order).indexOf(Actions.floorDecision(grant(have, max, pre), call(haveCtx), prof(esc + 1, need, needCtx)))
                    <= java.util.Arrays.asList(order).indexOf(Actions.floorDecision(grant(have, max, pre), call(haveCtx), prof(esc, need, needCtx))));
            }
    }

    // ---- digest invariance --------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    static Object shuffleKeys(Object o, Random r) {
        if (o instanceof Map) {
            List<String> ks = new ArrayList<>(((Map<String, Object>) o).keySet());
            java.util.Collections.shuffle(ks, r);
            Map<String, Object> out = new LinkedHashMap<>();
            for (String k : ks) out.put(k, shuffleKeys(((Map<String, Object>) o).get(k), r));
            return out;
        }
        if (o instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) o) out.add(shuffleKeys(x, r)); return out; }
        return o;
    }

    @Test
    @SuppressWarnings("unchecked")
    void digestIsInvariantUnderAuthoringNoiseAndSensitiveToDefinition() throws Exception {
        Map<String, Object> def = M(ActionVectorsTest.cases().stream().filter(x -> "digest-adv-review-excluded".equals(x.get("id"))).findFirst().get());
        Map<String, Object> d0 = M(M(def.get("input")).get("def"));
        String want = Actions.defDigest(d0);
        Random r = new Random(7);
        for (int i = 0; i < 20; i++) {
            Map<String, Object> d = M(shuffleKeys(d0, r));
            List<Object> al = new ArrayList<>((List<Object>) d.get("aliases")); java.util.Collections.reverse(al); d.put("aliases", al);
            d.put("review", new LinkedHashMap<String, Object>(Map.of("state", "authored"))); d.put("since", "1.0.0"); d.remove("examples");
            assertEquals(want, Actions.defDigest(d));
        }
        Map<String, Object> t = M(shuffleKeys(d0, r)); t.put("title", t.get("title") + "x");
        assertFalse(want.equals(Actions.defDigest(t)));
        Map<String, Object> e = M(shuffleKeys(d0, r)); e.put("effects", new ArrayList<Object>(List.of("read")));
        assertFalse(want.equals(Actions.defDigest(e)));
    }

    // ---- rule 22 exact refusals ---------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    static Map<String, Object> honestVerb() throws Exception {
        Map<String, Object> c = ActionVectorsTest.cases().stream().filter(x -> "schema-verb-adv-honest".equals(x.get("id"))).findFirst().get();
        return M(M(c.get("input")).get("verb"));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> deep(Map<String, Object> v) { return M(IntentJs.normalize(Json.parseLenient(Json.canonicalize(v)))); }

    static final String FLOOR = "schema_floor_forged: floors are below the floor of the carried traits";

    @Test
    @SuppressWarnings("unchecked")
    void ruleTwentyTwoRefusesEveryLoweringExactlyAndAcceptsTheFloor() throws Exception {
        Map<String, Object> v = honestVerb();
        assertNull(Actions.schemaVerbFloorError(v, Actions.CORE_REGISTRY));
        // one below the floor of the carried traits, field by field (the verb may carry MORE than the floor, e.g. an exact blast)
        Actions.Profile floor = Actions.floorOf(Actions.CORE_REGISTRY, (List<?>) v.get("traits"));
        long[] floorOf = {floor.risk, floor.blastPpm, floor.esc};
        String[] fields = {"risk", "blast_ppm", "esc"};
        for (int i = 0; i < fields.length; i++) {
            String f = fields[i];
            Map<String, Object> w = deep(v);
            Map<String, Object> fl = M(w.get("floors"));
            assertTrue(floorOf[i] > 0, f);
            fl.put(f, n(floorOf[i] - 1));
            assertEquals(FLOOR, Actions.schemaVerbFloorError(w, Actions.CORE_REGISTRY), f);
            fl.put(f, n(floorOf[i]));   // exactly the floor is allowed
            assertNull(Actions.schemaVerbFloorError(w, Actions.CORE_REGISTRY), f);
            fl.put(f, n(f.equals("blast_ppm") ? floorOf[i] + 1 : Math.min(3, floorOf[i] + 1)));   // raising is always allowed
            assertNull(Actions.schemaVerbFloorError(w, Actions.CORE_REGISTRY), f);
        }
        for (String f : new String[] {"caveats", "context", "prules"}) {
            Map<String, Object> w = deep(v);
            List<Object> l = (List<Object>) M(w.get("floors")).get(f);
            l.remove(l.size() - 1);
            assertEquals(FLOOR, Actions.schemaVerbFloorError(w, Actions.CORE_REGISTRY));
        }
        Map<String, Object> rev = deep(v); M(rev.get("floors")).put("rev", "rate_limited");
        assertEquals(FLOOR, Actions.schemaVerbFloorError(rev, Actions.CORE_REGISTRY));
        Map<String, Object> low = deep(v); M(low.get("floors")).put("rev", "reversible");
        assertEquals(FLOOR, Actions.schemaVerbFloorError(low, Actions.CORE_REGISTRY));
    }

    @Test
    @SuppressWarnings("unchecked")
    void ruleTwentyTwoRefusesDroppedUnknownAndV1Traits() throws Exception {
        Map<String, Object> v = honestVerb();
        for (String t : new String[] {"pca.money_moving", "pca.irreversible"}) {
            Map<String, Object> w = deep(v);
            ((List<Object>) w.get("traits")).remove(t);
            assertEquals("schema_traits_forged: missing implied trait " + t, Actions.schemaVerbFloorError(w, Actions.CORE_REGISTRY));
        }
        Map<String, Object> u = deep(v); ((List<Object>) u.get("traits")).add("pca.zzz");
        assertEquals("unknown_trait: unknown trait 'pca.zzz'", Actions.schemaVerbFloorError(u, Actions.CORE_REGISTRY));
        Map<String, Object> v1 = deep(v); v1.remove("floors");
        assertEquals("schema_floor_forged: not a v2 verb", Actions.schemaVerbFloorError(v1, Actions.CORE_REGISTRY));
        Map<String, Object> v1b = deep(v); v1b.remove("traits");
        assertEquals("schema_floor_forged: not a v2 verb", Actions.schemaVerbFloorError(v1b, Actions.CORE_REGISTRY));
    }
}
