package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * PCA 0.4.1: per-suite threshold-share wire validation, the policy-layer root-caveat helpers
 * ({@link Caveats#policyCaveats} / {@link Caveats#evaluateCaveats}, incl. {@code max_spend}) and the strict
 * {@code PCA-Action} header decoder ({@link Pca#decodePcaHeader}).
 */
public class R041Test {
    static Map<String, Object> map(Object... kv) { return PcaUnitTest.map(kv); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    static String b(int n) { return Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[n]); }
    static Json.Num n(String raw) { return new Json.Num(raw); }

    // ---- Fix 2: share signature per suite ----------------------------------------------------------------

    static Map<String, Object> share(Object... extra) {
        Map<String, Object> s = map("role", "guardian", "publicKey", b(32));
        for (int i = 0; i < extra.length; i += 2) s.put((String) extra[i], extra[i + 1]);
        return s;
    }

    @Test void shareWireAcceptsEachImplementedSuite() {
        assertNull(Pq.validateShareSignatureWire(share("sig", b(64))));
        assertNull(Pq.validateShareSignatureWire(share("alg", "ed25519", "sig", b(64))));
        assertNull(Pq.validateShareSignatureWire(share("alg", "ml-dsa-65", "sig", b(3309))));
        assertNull(Pq.validateShareSignatureWire(share("alg", "hybrid-ed25519-ml-dsa-65", "sig", b(64), "pq_sig", b(3309))));
        // pq_pk on a share is an optional echo judged by the threshold check, never by wire
        assertNull(Pq.validateShareSignatureWire(share("alg", "ml-dsa-65", "sig", b(3309), "pq_pk", "junk")));
        assertNull(Pq.validateShareSignatureWire(share("sig", b(64), "pq_pk", b(1952))));
    }

    @Test void shareWireRefusesWrongLengthsAndFields() {
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pq.validateShareSignatureWire(share("sig", b(3309))));
        assertNotNull(Pq.validateShareSignatureWire(share("alg", "ed25519", "sig", b(3309))));
        assertEquals("'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'",
            Pq.validateShareSignatureWire(share("alg", "ml-dsa-65", "sig", b(3308))));
        assertNotNull(Pq.validateShareSignatureWire(share("alg", "ml-dsa-65", "sig", b(3310))));
        assertNotNull(Pq.validateShareSignatureWire(share("alg", "ml-dsa-65", "sig", b(64))));
        assertEquals("'pq_sig' is not canonical base64url (3309 bytes) for alg 'hybrid-ed25519-ml-dsa-65'",
            Pq.validateShareSignatureWire(share("alg", "hybrid-ed25519-ml-dsa-65", "sig", b(64))));
        assertNotNull(Pq.validateShareSignatureWire(share("alg", "hybrid-ed25519-ml-dsa-65", "sig", b(64), "pq_sig", b(3308))));
        assertNotNull(Pq.validateShareSignatureWire(share("alg", "hybrid-ed25519-ml-dsa-65", "sig", b(3309), "pq_sig", b(3309))));
        assertEquals("'pq_sig' must be absent for alg 'ed25519'", Pq.validateShareSignatureWire(share("sig", b(64), "pq_sig", b(3309))));
        assertEquals("'pq_sig' must be absent for alg 'ml-dsa-65'",
            Pq.validateShareSignatureWire(share("alg", "ml-dsa-65", "sig", b(3309), "pq_sig", b(3309))));
        assertEquals("'pq_sig' must be absent for alg 'ed25519'", Pq.validateShareSignatureWire(share("sig", b(64), "pq_sig", null)));
        assertEquals("unknown signature alg 'ml-dsa-87'", Pq.validateShareSignatureWire(share("alg", "ml-dsa-87", "sig", b(4627))));
        assertEquals("'alg' must be a string", Pq.validateShareSignatureWire(share("alg", n("1"), "sig", b(64))));
        assertEquals("'alg' must be a string", Pq.validateShareSignatureWire(share("alg", null, "sig", b(64))));
        assertNotNull(Pq.validateShareSignatureWire(share("alg", "ml-dsa-65", "sig", b(3309) + "=")));
        assertNotNull(Pq.validateShareSignatureWire(share()));
    }

    // ---- Fix 1: policy caveats ---------------------------------------------------------------------------

    static Map<String, Object> ctx(Object amount) {
        Map<String, Object> params = map("amount", amount);
        return map("now", n("1800000000000"), "action", map("verb", "pay", "resource", "invoice:42", "reversibility_class", "reversible", "params", params));
    }

    static Caveats.Result ev(Object caveats, Object c) { return Caveats.evaluateCaveats(caveats, c); }

    @Test void maxSpend() {
        Object cv = list(map("type", "max_spend", "usd", n("100")));
        assertTrue(ev(cv, ctx(n("100"))).ok);
        assertTrue(ev(cv, ctx(n("99.5"))).ok);
        assertTrue(ev(cv, ctx(n("0"))).ok);
        assertFalse(ev(cv, ctx(n("150"))).ok);
        assertEquals(List.of("max_spend"), ev(cv, ctx(n("150"))).failed);
        assertFalse(ev(cv, ctx(n("-1"))).ok);
        assertFalse(ev(cv, ctx("100")).ok);
        assertFalse(ev(cv, ctx(true)).ok);
        assertFalse(ev(cv, ctx(null)).ok);
        assertFalse(ev(cv, ctx(n("1e400"))).ok); // not finite (JSON number overflows to Infinity)
        // programmatic Java numbers are numbers too
        assertTrue(ev(list(map("type", "max_spend", "usd", 100)), ctx(42L)).ok);
        assertTrue(ev(list(map("type", "max_spend", "usd", new BigDecimal("100.5"))), ctx(100.25d)).ok);
        assertFalse(ev(list(map("type", "max_spend", "usd", 100)), ctx(Double.NaN)).ok);
        // the limit
        assertFalse(ev(list(map("type", "max_spend", "usd", "100")), ctx(n("1"))).ok);
        assertFalse(ev(list(map("type", "max_spend", "usd", n("-1"))), ctx(n("0"))).ok);
        assertFalse(ev(list(map("type", "max_spend")), ctx(n("0"))).ok);
        assertFalse(ev(list(map("type", "max_spend", "usd", n("1e400"))), ctx(n("1"))).ok);
        // max_spend does not need `now`
        Map<String, Object> noNow = ctx(n("5"));
        noNow.remove("now");
        assertTrue(ev(cv, noNow).ok);
    }

    @SuppressWarnings("unchecked")
    @Test void maxSpendCurrencyAndShape() {
        Object cv = list(map("type", "max_spend", "usd", n("100")));
        for (Object cur : new Object[] {"usd", "USD"}) {
            Map<String, Object> c = ctx(n("5"));
            ((Map<String, Object>) ((Map<String, Object>) c.get("action")).get("params")).put("currency", cur);
            assertTrue(ev(cv, c).ok, String.valueOf(cur));
        }
        for (Object cur : new Object[] {"eur", "Usd", null, n("1"), list("usd")}) {
            Map<String, Object> c = ctx(n("5"));
            ((Map<String, Object>) ((Map<String, Object>) c.get("action")).get("params")).put("currency", cur);
            assertFalse(ev(cv, c).ok, String.valueOf(cur));
        }
        Map<String, Object> c = ctx(n("5"));
        ((Map<String, Object>) c.get("action")).put("params", list(n("5")));
        assertFalse(ev(cv, c).ok);
        ((Map<String, Object>) c.get("action")).remove("params");
        assertFalse(ev(cv, c).ok);
        ((Map<String, Object>) c.get("action")).put("params", map());
        assertFalse(ev(cv, c).ok);
        c.put("action", "pay");
        assertFalse(ev(cv, c).ok);
        c.remove("action");
        assertFalse(ev(cv, c).ok);
    }

    @Test void timeAndContextCaveats() {
        Map<String, Object> c = map("now", n("1000"), "delegation_depth", n("2"), "blast_radius", n("5"),
            "reversibility_class", "rate_limited", "recent_action_times", list(n("1000"), n("500"), n("0"), "x", n("1001")));
        assertTrue(ev(list(map("type", "expires", "at", n("1001"))), c).ok);
        assertFalse(ev(list(map("type", "expires", "at", n("1000"))), c).ok);
        assertTrue(ev(list(map("type", "not_before", "at", n("1000"))), c).ok);
        assertFalse(ev(list(map("type", "not_before", "at", n("1001"))), c).ok);
        assertFalse(ev(list(map("type", "not_before", "at", "0")), c).ok);
        // rate: window (now - 1000, now] = (0, 1000], so 1000 and 500 count; 0, "x" and 1001 do not
        assertTrue(ev(list(map("type", "rate", "max", n("3"), "per_secs", n("1"))), c).ok);
        assertFalse(ev(list(map("type", "rate", "max", n("2"), "per_secs", n("1"))), c).ok);
        assertFalse(ev(list(map("type", "rate", "max", n("3"), "per_secs", n("0"))), c).ok);
        assertTrue(ev(list(map("type", "max_blast_radius", "max", n("5"))), c).ok);
        assertFalse(ev(list(map("type", "max_blast_radius", "max", n("4"))), c).ok);
        assertTrue(ev(list(map("type", "reversibility_max", "class", "rate_limited")), c).ok);
        assertTrue(ev(list(map("type", "reversibility_max", "class", "irreversible")), c).ok);
        assertFalse(ev(list(map("type", "reversibility_max", "class", "reversible")), c).ok);
        assertFalse(ev(list(map("type", "reversibility_max", "class", list("irreversible"))), c).ok);
        assertTrue(ev(list(map("type", "delegation_depth", "max", n("2"))), c).ok);
        assertFalse(ev(list(map("type", "delegation_depth", "max", n("1"))), c).ok);
        assertTrue(ev(list(map("type", "budget_alloc", "limit", n("0"))), c).ok);
        assertFalse(ev(list(map("type", "budget_alloc", "limit", n("-1"))), c).ok);
        for (String t : new String[] {"note", "envelope", "resource_prefix", "predicates", "tool_schema", "nope"})
            assertFalse(ev(list(map("type", t)), c).ok, t);
        // missing context fields
        Map<String, Object> bare = map("now", n("1000"));
        for (Object cv : new Object[] {map("type", "rate", "max", n("3"), "per_secs", n("1")), map("type", "max_blast_radius", "max", n("5")),
                map("type", "reversibility_max", "class", "irreversible"), map("type", "delegation_depth", "max", n("9"))})
            assertFalse(ev(list(cv), bare).ok, String.valueOf(cv));
        // no `now`: every time/context caveat is unsatisfied
        assertFalse(ev(list(map("type", "budget_alloc", "limit", n("1"))), map()).ok);
        assertFalse(ev(list(map("type", "expires", "at", n("1"))), map("now", "1000")).ok);
    }

    @Test void evaluateIsTotalAndOrdered() {
        Caveats.Result r = ev("nope", map());
        assertFalse(r.ok);
        assertEquals(List.of("<malformed caveats>"), r.failed);
        r = ev(null, map());
        assertEquals(List.of("<malformed caveats>"), r.failed);
        r = ev(list(map("type", "note"), "x", map("type", n("1")), map("type", "budget_alloc", "limit", n("1")), map("type", "expires", "at", n("0"))),
            map("now", n("5")));
        assertFalse(r.ok);
        assertEquals(List.of("note", "<malformed>", "<malformed>", "expires"), r.failed);
        r = ev(list(), null);
        assertTrue(r.ok);
        assertEquals(List.of(), r.failed);
        assertFalse(ev(list(map("type", "budget_alloc", "limit", n("1"))), "ctx").ok);
    }

    @Test void policyCaveatsDropsFirstEnvelopeAndAppendsHopCaveats() {
        Map<String, Object> env = map("type", "envelope", "x", n("1"));
        Map<String, Object> env2 = map("type", "envelope", "x", n("2"));
        Map<String, Object> spend = map("type", "max_spend", "usd", n("10"));
        Map<String, Object> grant = map("caveats", list(spend, env, env2));
        assertEquals(list(spend, env2), Caveats.policyCaveats(grant, null));
        assertEquals(list(spend, env2), Caveats.rootCaveats(grant));
        Map<String, Object> hopCv = map("type", "expires", "at", n("9"));
        Map<String, Object> leaf = map("caveats", list(spend, env, env2, hopCv));
        assertEquals(list(spend, env2, hopCv), Caveats.policyCaveats(grant, list(grant, leaf)));
        assertEquals(list(spend, env2), Caveats.policyCaveats(grant, list()));
        assertEquals(list(spend, env2), Caveats.policyCaveats(grant, "chain"));
        assertEquals(list(spend, env2), Caveats.policyCaveats(grant, list(map("caveats", "x"))));
        assertEquals(list(spend, env2), Caveats.policyCaveats(grant, list("leaf")));
        // a leaf with fewer caveats than the grant appends nothing
        assertEquals(list(spend, env2), Caveats.policyCaveats(grant, list(map("caveats", list()))));
        // non-array root caveats pass through and are refused by evaluateCaveats
        assertEquals("x", Caveats.policyCaveats(map("caveats", "x"), list(leaf)));
        assertNull(Caveats.policyCaveats("grant", null));
        assertEquals(List.of("<malformed caveats>"), Caveats.evaluateCaveats(Caveats.policyCaveats(map(), null), map()).failed);
        // the input list is not mutated
        assertEquals(3, ((List<?>) grant.get("caveats")).size());
    }

    // ---- Fix 3: strict PCA-Action header ------------------------------------------------------------------

    @Test void decodePcaHeaderStrict() {
        assertEquals("{\"a\":1}", Pca.decodePcaHeader("eyJhIjoxfQ"));
        assertEquals("﻿{}", Pca.decodePcaHeader("77u_e30")); // BOM kept
        assertEquals("\"é😀\"", Pca.decodePcaHeader("IsOp8J-YgCI"));
        for (String bad : new String[] {"", "eyJhIjoxfQ==", "Ij8/PyI", "In5+fj4i", " e30", "e30 ", "e30\t", "eyJh IjoxfQ", "eyJhIjox\nfQ",
                "eyJhIjox*fQ", "eyJhI", "QR", "QUJ", "__57", "IsCvIg", "Iu2ggCI", "IuKC"})
            assertNull(Pca.decodePcaHeader(bad), bad);
        assertNull(Pca.decodePcaHeader(null));
    }

    // ---- the corpus sections, from JUnit (the JUnit-free ConformanceTest runs them too) ---------------------

    @SuppressWarnings("unchecked")
    @Test void corpusCaveatEvalAndHeader() throws Exception {
        Map<String, Object> doc = ReasonSnapshot.loadJson("vectors.json");
        Map<String, Object> prim = (Map<String, Object>) doc.get("primitives");
        int n = 0;
        boolean sawDeny = false, sawAllow = false;
        for (Object x : (List<Object>) prim.get("caveat_eval")) {
            Map<String, Object> e = (Map<String, Object>) x;
            Map<String, Object> exp = (Map<String, Object>) e.get("expect");
            Caveats.Result r = Caveats.evaluateCaveats(Caveats.policyCaveats(e.get("grant"), e.get("chain")), e.get("context"));
            assertEquals(exp.get("allow"), r.ok, String.valueOf(e.get("name")));
            assertEquals(exp.get("failed"), r.failed, String.valueOf(e.get("name")));
            if ("r041-root-max-spend-exceeded".equals(e.get("name"))) sawDeny = !r.ok;
            if ("r041-root-max-spend-within".equals(e.get("name"))) sawAllow = r.ok;
            n++;
        }
        assertTrue(n >= 40 && sawDeny && sawAllow, "caveat_eval ran " + n);
        int h = 0;
        for (Object x : (List<Object>) prim.get("pca_header")) {
            Map<String, Object> e = (Map<String, Object>) x;
            String got = Pca.decodePcaHeader((String) e.get("input"));
            assertEquals(Boolean.TRUE.equals(e.get("valid")), got != null, String.valueOf(e.get("name")));
            if (got != null) assertEquals(e.get("text"), got, String.valueOf(e.get("name")));
            h++;
        }
        assertTrue(h >= 27, "pca_header ran " + h);
    }
}
