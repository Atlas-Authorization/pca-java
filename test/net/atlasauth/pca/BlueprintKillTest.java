package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link Blueprint}: every well-formedness rule at its boundary (wellFormed directly, so the
 * signature check cannot mask a rule), the registry outcomes with their exact code and replaced flag (records signed here),
 * and every check() decision with all of its fields.
 */
public class BlueprintKillTest {
    static final Keys.EdKey OP = Keys.edFromSeed(seed(1));
    static final Keys.EdKey OP2 = Keys.edFromSeed(seed(2));

    static byte[] seed(int b) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) b);
        return s;
    }

    static Map<String, Object> base() {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", 1);
        b.put("id", "bp");
        b.put("key", "K");
        b.put("ceiling", new ArrayList<>());
        b.put("epoch", 1);
        b.put("status", "active");
        b.put("issued_at", 0);
        b.put("operator", OP.id());
        return b;
    }

    static Map<String, Object> with(String k, Object v) {
        Map<String, Object> b = base();
        if (v == DEL) b.remove(k);
        else b.put(k, v);
        return b;
    }

    static final Object DEL = new Object();

    static String rep(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append('a');
        return sb.toString();
    }

    /** Signs exactly the body keys present, like an operator does. */
    static Map<String, Object> signed(Map<String, Object> b, Keys.EdKey k) {
        Map<String, Object> body = new LinkedHashMap<>(b);
        body.remove("sig");
        byte[] msg = Pca.concat(Blueprint.DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
        Map<String, Object> out = new LinkedHashMap<>(b);
        out.put("sig", Pca.b64(k.sign(msg)));
        return out;
    }

    static List<Object> ceiling(int n, Object item) {
        List<Object> c = new ArrayList<>();
        for (int i = 0; i < n; i++) c.add(item);
        return c;
    }

    static Map<String, Object> typed() {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("type", "t");
        return t;
    }

    @Test
    void wellFormedEveryRule() {
        assertTrue(Blueprint.wellFormed(base()));
        assertFalse(Blueprint.wellFormed("x"));
        assertFalse(Blueprint.wellFormed(null));
        assertFalse(Blueprint.wellFormed(with("v", 2)));
        assertFalse(Blueprint.wellFormed(with("v", 0)));
        assertFalse(Blueprint.wellFormed(with("v", "1")));
        assertFalse(Blueprint.wellFormed(with("v", DEL)));
        for (String k : new String[] {"id", "key", "operator"}) {
            assertFalse(Blueprint.wellFormed(with(k, DEL)), k);
            assertFalse(Blueprint.wellFormed(with(k, "")), k);
            assertFalse(Blueprint.wellFormed(with(k, 7)), k);
            assertTrue(Blueprint.wellFormed(with(k, "a")), k);
            assertTrue(Blueprint.wellFormed(with(k, rep(128))), k);
            assertFalse(Blueprint.wellFormed(with(k, rep(129))), k);
        }
        for (String k : new String[] {"epoch", "issued_at"}) {
            assertTrue(Blueprint.wellFormed(with(k, 0)), k);
            assertTrue(Blueprint.wellFormed(with(k, 1)), k);
            assertFalse(Blueprint.wellFormed(with(k, -1)), k);
            assertFalse(Blueprint.wellFormed(with(k, DEL)), k);
            assertFalse(Blueprint.wellFormed(with(k, new Json.Num("1.5"))), k);
        }
        assertTrue(Blueprint.wellFormed(with("status", "disabled")));
        assertFalse(Blueprint.wellFormed(with("status", "x")));
        assertFalse(Blueprint.wellFormed(with("status", DEL)));
        assertTrue(Blueprint.wellFormed(with("max_depth", 1)));
        assertTrue(Blueprint.wellFormed(with("max_depth", 2)));
        assertFalse(Blueprint.wellFormed(with("max_depth", 0)));
        assertFalse(Blueprint.wellFormed(with("max_depth", -1)));
        assertFalse(Blueprint.wellFormed(with("max_depth", "1")));
        assertFalse(Blueprint.wellFormed(with("max_depth", null)));
        assertTrue(Blueprint.wellFormed(with("expires_at", 0)));
        assertTrue(Blueprint.wellFormed(with("expires_at", 5)));
        assertFalse(Blueprint.wellFormed(with("expires_at", -1)));
        assertFalse(Blueprint.wellFormed(with("expires_at", null)));
        assertFalse(Blueprint.wellFormed(with("ceiling", DEL)));
        assertFalse(Blueprint.wellFormed(with("ceiling", "x")));
        assertTrue(Blueprint.wellFormed(with("ceiling", ceiling(1, typed()))));
        assertTrue(Blueprint.wellFormed(with("ceiling", ceiling(32, typed()))));
        assertFalse(Blueprint.wellFormed(with("ceiling", ceiling(33, typed()))));
        assertFalse(Blueprint.wellFormed(with("ceiling", ceiling(1, "t"))));
        assertFalse(Blueprint.wellFormed(with("ceiling", ceiling(1, new LinkedHashMap<String, Object>()))));
        Map<String, Object> notStr = new LinkedHashMap<>();
        notStr.put("type", 1);
        assertFalse(Blueprint.wellFormed(with("ceiling", ceiling(1, notStr))));
    }

    @Test
    void verifyNeedsWellFormedAndSignature() {
        assertTrue(Blueprint.verify(signed(base(), OP)));
        // a valid signature over a malformed record is still refused
        assertFalse(Blueprint.verify(signed(with("status", "x"), OP)));
        assertFalse(Blueprint.verify(signed(with("v", 2), OP)));
        assertFalse(Blueprint.verify(signed(base(), OP2)));
        assertFalse(Blueprint.verify(base()));
        assertFalse(Blueprint.verify("x"));
    }

    static void acc(Blueprint.Accept a, String code, boolean replaced) {
        assertNotNull(a);
        assertEquals(code, a.code);
        assertEquals(replaced, a.replaced);
    }

    @Test
    void registryOutcomes() {
        Blueprint.Registry r = new Blueprint.Registry(Arrays.asList(OP.id(), OP2.id()), new MemoryAtomicKv());
        assertEquals(0, r.epoch());
        acc(r.accept(base()), "bad_record", false);
        acc(r.accept(signed(with("operator", Keys.edFromSeed(seed(3)).id()), Keys.edFromSeed(seed(3)))), "unknown_operator", false);
        Map<String, Object> e5 = signed(with("epoch", 5), OP);
        acc(r.accept(e5), null, true);
        assertEquals(5, r.epoch());
        acc(r.accept(e5), null, false); // the same record again
        acc(r.accept(signed(with("epoch", 4), OP)), "stale_epoch", false);
        Map<String, Object> fork = with("epoch", 5);
        fork.put("issued_at", 9);
        acc(r.accept(signed(fork, OP)), "epoch_fork", false);
        Map<String, Object> other = with("epoch", 6);
        other.put("operator", OP2.id());
        acc(r.accept(signed(other, OP2)), "operator_changed", false);
        acc(r.accept(signed(with("epoch", 6), OP)), null, true);
        assertEquals(6, r.epoch());
    }

    /** Stores a record as the registry would hold it after accepting it (the record and the highest epoch). */
    static void put(MemoryAtomicKv kv, String key, Map<String, Object> rec) {
        kv.set("blueprint/" + key, rec);
        Object cur = kv.get("blueprint/max");
        long have = cur == null ? 0 : Json.asLong(((Map<?, ?>) cur).get("epoch"));
        if (Json.asLong(rec.get("epoch")) > have) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("epoch", rec.get("epoch"));
            kv.set("blueprint/max", m);
        }
    }

    @Test
    void epochIsTheMaximum() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Blueprint.Registry r = new Blueprint.Registry(new ArrayList<>(), kv);
        put(kv, "a", with("epoch", 9));
        put(kv, "b", with("epoch", 1));
        assertEquals(9, r.epoch());
        put(kv, "a", with("epoch", 1));
        put(kv, "b", with("epoch", 9));
        assertEquals(9, r.epoch());
    }

    static Map<String, Object> hop(Object issuer, Object holder) {
        Map<String, Object> h = new LinkedHashMap<>();
        if (issuer != DEL) h.put("issuer", issuer);
        if (holder != DEL) h.put("holder", holder);
        return h;
    }

    static List<Object> chain(Object... hops) { return new ArrayList<>(Arrays.asList(hops)); }

    static void dec(Blueprint.Decision d, String decision, String code, String bp, List<String> governed, long have, long need) {
        assertNotNull(d);
        assertEquals(decision, d.decision);
        assertEquals(code, d.code);
        assertEquals(bp, d.blueprint);
        assertEquals(governed, d.governed);
        assertEquals(have, d.have);
        assertEquals(need, d.need);
    }

    static Blueprint.Registry reg(Map<String, Object> rec) {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        put(kv, (String) rec.get("key"), rec);
        return new Blueprint.Registry(new ArrayList<>(), kv);
    }

    static final List<String> NONE = new ArrayList<>();
    static final List<String> BP = Arrays.asList("bp");

    @Test
    void checkInputs() {
        Blueprint.Registry r = reg(base());
        List<Object> ok = chain(hop("P", "K"), hop("K", "i"));
        dec(Blueprint.check(ok, r, 0, "require", null), "allow", null, null, BP, 0, 0);
        dec(Blueprint.check("x", r, 0, "require", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(), r, 0, "require", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(ok, r, -1, "require", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(ok, r, "0", "require", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", "K"), "x"), r, 0, "require", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain("x", hop("P", "K")), r, 0, "any", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop(DEL, "K")), r, 0, "any", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", DEL)), r, 0, "any", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop("", "K")), r, 0, "any", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", "")), r, 0, "any", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop(rep(129), "K")), r, 0, "any", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", rep(129))), r, 0, "any", null), "deny", "bad_input", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop(rep(128), rep(128))), r, 0, "any", null), "allow", null, null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop(rep(128), rep(128))), r, 0, "require", null), "deny", "no_blueprint", null, NONE, 0, 0);
    }

    @Test
    void checkRules() {
        List<Object> ok = chain(hop("P", "K"), hop("K", "i"));
        dec(Blueprint.check(ok, reg(base()), 0, "require", 1L), "allow", null, null, BP, 0, 0);
        dec(Blueprint.check(ok, reg(base()), 0, "require", 2L), "escalate", "stale_blueprint_state", null, NONE, 1, 2);
        dec(Blueprint.check(ok, new Blueprint.Registry(new ArrayList<>(), new MemoryAtomicKv()), 0, "any", 1L), "escalate", "stale_blueprint_state", null, NONE, 0, 1);
        // the blueprint key issuing the first hop, and a hop whose previous holder is not the key: broken links
        dec(Blueprint.check(chain(hop("K", "i")), reg(base()), 0, "require", null), "deny", "broken_link", "bp", NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", "Q"), hop("K", "i")), reg(base()), 0, "require", null), "deny", "broken_link", "bp", NONE, 0, 0);
        dec(Blueprint.check(ok, reg(with("status", "disabled")), 0, "require", null), "deny", "blueprint_disabled", "bp", NONE, 0, 0);
        dec(Blueprint.check(ok, reg(with("expires_at", 10)), 9, "require", null), "allow", null, null, BP, 0, 0);
        dec(Blueprint.check(ok, reg(with("expires_at", 10)), 10, "require", null), "deny", "blueprint_expired", "bp", NONE, 0, 0);
        dec(Blueprint.check(ok, reg(with("expires_at", 10)), 11, "require", null), "deny", "blueprint_expired", "bp", NONE, 0, 0);
        // max_depth counts the hops from the governed one to the end
        dec(Blueprint.check(ok, reg(with("max_depth", 1)), 0, "require", null), "allow", null, null, BP, 0, 0);
        dec(Blueprint.check(chain(hop("P", "K"), hop("K", "i"), hop("i", "j")), reg(with("max_depth", 1)), 0, "require", null),
            "deny", "too_deep", "bp", NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", "K"), hop("K", "i"), hop("i", "j")), reg(with("max_depth", 2)), 0, "require", null),
            "allow", null, null, BP, 0, 0);
        dec(Blueprint.check(chain(hop("P", "K"), hop("K", "i"), hop("i", "j")), reg(base()), 0, "require", null), "allow", null, null, BP, 0, 0);
        dec(Blueprint.check(ok, reg(with("ceiling", ceiling(1, typed()))), 0, "require", null), "deny", "ceiling_unevaluable", "bp", NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", "Q")), reg(base()), 0, "require", null), "deny", "no_blueprint", null, NONE, 0, 0);
        dec(Blueprint.check(chain(hop("P", "Q")), reg(base()), 0, "any", null), "allow", null, null, NONE, 0, 0);
    }
}
