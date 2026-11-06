package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link CaveatLang}: self-signed narrow blocks (Ed25519 and ML-DSA-65 under the leaf's holder_pq),
 * self-signed discharges, the K1 evaluator's binds / id dedupe / error path, result objects, and hop attribution.
 */
public class CaveatLangRestKillTest {
    static final byte[] SEED = new byte[32];
    static final String PUB;
    static {
        Arrays.fill(SEED, (byte) 11);
        byte[] pk = new byte[32];
        Ed25519.generatePublicKey(SEED, 0, pk, 0);
        PUB = Pca.b64(pk);
    }
    static final String NONCE = "CQkJCQkJCQkJCQkJCQkJCQ";
    static final String CAPH = Pca.b64(new byte[32]);

    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }
    static String ed(byte[] msg) {
        byte[] sig = new byte[64];
        Ed25519.sign(SEED, 0, msg, 0, msg.length, sig, 0);
        return Pca.b64(sig);
    }

    /** A thrower for a get() inside a verifier's try: null message reads "unknown". */
    static Map<String, Object> hostile(String msg) {
        return new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw msg == null ? new IllegalStateException() : new IllegalStateException(msg); }
        };
    }

    // ---- narrow ----

    static Map<String, Object> leaf(String holderPq) {
        Map<String, Object> l = m("holder", PUB, "caveats", List.of(m("type", "max_amount", "max", n(100))));
        if (holderPq != null) l.put("holder_pq", holderPq);
        return l;
    }

    static Map<String, Object> narrow(Map<String, Object> leaf, AsymmetricCipherKeyPair pqk) {
        Map<String, Object> nb = m("v", n(1), "kind", "pca-narrow", "cap_hash", Pca.capHash(leaf), "holder", PUB,
            "caveats", List.of(m("type", "x")), "iat", n(1000), "not_after", n(2000), "nonce", NONCE);
        if (pqk != null) {
            nb.put("alg", "ml-dsa-65");
            nb.put("pq_pk", PqChainTest.pk(pqk));
        }
        byte[] msg = IntentArtifacts.artifactMessage(CaveatLang.NARROW_DOMAIN, nb);
        nb.put("sig", pqk == null ? ed(msg) : PqChainTest.pqSign(pqk, msg));
        return nb;
    }

    static String nv(CaveatLang.NarrowVerdict v) { return v.ok ? "ok " + v.caveats : v.reason; }

    @Test void narrowEd25519AndNormalized() {
        Map<String, Object> l = leaf(null);
        Map<String, Object> nb = narrow(l, null);
        CaveatLang.NarrowVerdict v = CaveatLang.verifyNarrow(nb, l, null, m("now", n(1500)));
        assertEquals("ok [{type=x}]", nv(v));
        assertEquals("NarrowVerdict{ok}", v.toString());
        // 1000.0 is the integer 1000 the block was signed over: verified after normalization
        nb.put("iat", new Json.Num("1000.0"));
        assertEquals("ok [{type=x}]", nv(CaveatLang.verifyNarrow(nb, l, null, m("now", n(1500)))));
        CaveatLang.NarrowVerdict no = CaveatLang.verifyNarrow(nb, l, null, m("now", n(2001)));
        assertEquals("the narrow block has expired", no.reason);
        assertEquals("NarrowVerdict{the narrow block has expired}", no.toString());
    }

    @Test void narrowPqOnlyUnderTheCommittedKey() {
        AsymmetricCipherKeyPair k = PqChainTest.pqKey(), other = PqChainTest.pqKey();
        Map<String, Object> l = leaf(Pca.holderPqCommitment(PqChainTest.pk(k)));
        assertEquals("ok [{type=x}]", nv(CaveatLang.verifyNarrow(narrow(l, k), l, null, m("now", n(1500)))));
        Map<String, Object> wrong = leaf(Pca.holderPqCommitment(PqChainTest.pk(other)));
        assertEquals("narrow signature invalid", nv(CaveatLang.verifyNarrow(narrow(wrong, k), wrong, null, m("now", n(1500)))));
        Map<String, Object> none = leaf(null);
        assertEquals("narrow signature invalid", nv(CaveatLang.verifyNarrow(narrow(none, k), none, null, m("now", n(1500)))));
    }

    @Test void narrowErrorPath() {
        assertEquals("narrow error (fail closed): boom", CaveatLang.verifyNarrow(null, null, null, hostile("boom")).reason);
        assertEquals("narrow error (fail closed): unknown", CaveatLang.verifyNarrow(null, null, null, hostile(null)).reason);
    }

    // ---- discharge ----

    static Map<String, Object> caveat(Object require) {
        return m("type", "needs_discharge", "id", "kyc", "issuer", "risk-team", "issuer_class", "human", "bind", "chain_hop",
            "ttl_ms", n(600000), "require", require);
    }
    static final Map<String, Object> GTE = caveat(List.of(m("claim", "kyc_level", "op", "gte", "value", n(2))));

    static Map<String, Object> discharge() {
        Map<String, Object> d = m("v", n(1), "kind", "pca-discharge", "caveat_id", "kyc", "issuer", "risk-team", "cap_hash", CAPH,
            "bind", "chain_hop", "claims", m("kyc_level", n(3)), "iat", n(1000), "not_after", n(2000), "nonce", NONCE);
        d.put("sig", ed(IntentArtifacts.artifactMessage(CaveatLang.DISCHARGE_DOMAIN, d)));
        return d;
    }
    static Map<String, Object> pin(Object... extra) {
        Map<String, Object> p = m("label", "risk-team", "class", "human", "pk", PUB);
        p.putAll(m(extra));
        return p;
    }
    static Map<String, Object> bind(Map<String, Object> pin) { return m("cap_hash", CAPH, "pins", List.of(pin), "now", n(1500)); }
    static String dv(CaveatLang.DischargeVerdict v) { return v.ok ? "ok " + v.digest + " " + v.claims : v.reason; }

    @Test void dischargeOkAndBound() {
        Map<String, Object> d = discharge();
        String want = "ok " + CaveatLang.dischargeDigest(d) + " {kyc_level=3}";
        CaveatLang.DischargeVerdict v = CaveatLang.verifyDischarge(d, GTE, bind(pin()));
        assertEquals(want, dv(v));
        assertEquals("DischargeVerdict{ok, " + CaveatLang.dischargeDigest(d) + "}", v.toString());
        // a pin's SPIFFE ID is only compared when the caveat requires one
        assertEquals(want, dv(CaveatLang.verifyDischarge(d, GTE, bind(pin("spiffe_id", "spiffe://acme.test/x")))));
        // "in" is the switch default
        assertEquals(want, dv(CaveatLang.verifyDischarge(d, caveat(List.of(m("claim", "kyc_level", "op", "in", "value", List.of(n(1), n(3))))), bind(pin()))));
        assertEquals("claim 'kyc_level' does not satisfy the caveat",
            dv(CaveatLang.verifyDischarge(d, caveat(List.of(m("claim", "kyc_level", "op", "in", "value", List.of(n(1), n(2))))), bind(pin()))));
        // the signed iat 1000 spelled 1000.0 verifies after normalization
        Map<String, Object> d2 = discharge();
        d2.put("iat", new Json.Num("1000.0"));
        assertEquals(want, dv(CaveatLang.verifyDischarge(d2, GTE, bind(pin()))));
        CaveatLang.DischargeVerdict no = CaveatLang.verifyDischarge(d, GTE, m("cap_hash", CAPH, "now", n(1500)));
        assertEquals("DischargeVerdict{no issuer is pinned}", no.toString());
        assertEquals("discharge error (fail closed): boom", CaveatLang.verifyDischarge(d, GTE, hostile("boom")).reason);
        assertEquals("discharge error (fail closed): unknown", CaveatLang.verifyDischarge(d, GTE, hostile(null)).reason);
    }

    @Test void digests() {
        Map<String, Object> p = m("a", "b");
        assertEquals(Pca.hashCanonical(m("d", CaveatLang.DISCHARGE_ACTION_DOMAIN, "pcactn", p)), CaveatLang.dischargeActionDigest(p));
        assertEquals(Pca.hashCanonical(m("d", CaveatLang.DISCHARGE_REF_DOMAIN, "discharge", m("x", n(1)))),
            CaveatLang.dischargeDigest(m("x", new Json.Num("1.0"))));
    }

    // ---- K1 ----

    @Test void k1DischargeWithoutPinsIsNotPinned() {
        Map<String, Object> g = m("holder", PUB, "caveats", List.of(GTE));
        CaveatLang.K1Result r = CaveatLang.evaluateK1(g, null, m("discharges", List.of(discharge())), m("now", n(1500)));
        assertEquals(List.of("needs_discharge"), r.failed);
        assertEquals(List.of("the issuer is not pinned by this verifier"), r.reasons);
        assertEquals("K1Result{ok=false, failed=[needs_discharge]}", r.toString());
        assertEquals(1, r.bound.size());
        assertEquals(0, r.bound.get(0).hop);
        assertEquals(Pca.capHash(g), r.bound.get(0).capHash);
        assertThrows(UnsupportedOperationException.class, () -> r.failed.add("x"));
        assertThrows(UnsupportedOperationException.class, () -> r.reasons.add("x"));
        assertThrows(UnsupportedOperationException.class, () -> r.plain.add("x"));
        assertThrows(UnsupportedOperationException.class, () -> r.bound.add(null));
        CaveatLang.K1Result ok = CaveatLang.evaluateK1(m("caveats", List.of()), null, m(), m("now", n(0)));
        assertTrue(ok.ok);
        assertEquals("K1Result{ok=true, failed=[]}", ok.toString());
    }

    @Test void k1NumericIdDoesNotCollideWithItsText() {
        Map<String, Object> good = m("type", "max_uses", "id", "5", "n", n(1), "until", n(5000));
        Map<String, Object> bad = m("type", "max_uses", "id", n(5), "n", n(1), "until", n(5000));
        CaveatLang.K1Result r = CaveatLang.evaluateK1(m("caveats", List.of(good, bad)), null, m(), m("now", n(0)));
        assertEquals(List.of("max_uses"), r.failed);
        assertEquals(List.of("id is malformed"), r.reasons);
    }

    @Test void k1ErrorPath() {
        Map<String, Object> g = m("caveats", List.of());
        CaveatLang.K1Result r = CaveatLang.evaluateK1(g, null, m(), hostile("boom"));
        assertEquals(List.of("<malformed>"), r.failed);
        assertEquals(List.of("caveat language error (fail closed): boom"), r.reasons);
        assertEquals(List.of(), r.plain);
        assertEquals(List.of(), r.bound);
        assertEquals(List.of("caveat language error (fail closed): unknown"), CaveatLang.evaluateK1(g, null, m(), hostile(null)).reasons);
    }

    @Test void caveatsK1PassesTheActionToPredicates() {
        Map<String, Object> g = m("caveats", List.of(m("type", "predicates", "allow", List.of(m("verb", "pay")))));
        Caveats.Result ok = CaveatLang.evaluateCaveatsK1(g, null, null, m("now", n(0), "action", m("verb", "pay", "resource", "r")));
        assertTrue(ok.ok, String.valueOf(ok.failed));
        assertEquals(List.of(), ok.failed);
        Caveats.Result no = CaveatLang.evaluateCaveatsK1(g, null, null, m("now", n(0)));
        assertEquals(List.of("predicates"), no.failed);
        Caveats.Result mal = CaveatLang.evaluateCaveatsK1(m(), null, null, m("now", n(0)));
        assertFalse(mal.ok);
        assertEquals(List.of("<malformed caveats>", "<malformed>"), mal.failed);
    }

    // ---- hops / max_uses / derive ----

    @Test void boundCaveatsAttributesTheIntroducingHop() {
        Map<String, Object> a = m("type", "x"), b = m("type", "y");
        Map<String, Object> g = m("holder", "h0", "caveats", List.of(a));
        Map<String, Object> h1 = m("holder", "h1", "caveats", List.of(a, b));
        List<CaveatLang.BoundCaveat> bs = CaveatLang.boundCaveats(g, List.of(g, h1));
        assertEquals(2, bs.size());
        assertEquals(List.of(a, 0, Pca.capHash(g)), List.of(bs.get(0).caveat, bs.get(0).hop, bs.get(0).capHash));
        assertEquals(List.of(b, 1, Pca.capHash(h1)), List.of(bs.get(1).caveat, bs.get(1).hop, bs.get(1).capHash));
        assertNull(CaveatLang.boundCaveats(m("caveats", "x"), null));
        assertNull(CaveatLang.boundCaveats(m(), null));
        assertNull(CaveatLang.boundCaveats("x", null));
    }

    @Test void reserveMaxUsesEdges() {
        CaveatLang.UsesVerdict skip = CaveatLang.reserveMaxUses(new MemoryStateStore(), List.of(new CaveatLang.BoundCaveat("x", 0, "h")), 0L);
        assertTrue(skip.ok);
        assertEquals("UsesVerdict{ok, spent=0}", skip.toString());
        CaveatLang.UsesVerdict clock = CaveatLang.reserveMaxUses(new MemoryStateStore(), new ArrayList<>(), (Object) "x");
        assertFalse(clock.ok);
        assertEquals(0, clock.spent);
        assertEquals("UsesVerdict{the verifier clock is not a safe integer (fail closed)}", clock.toString());
        List<CaveatLang.BoundCaveat> mu = List.of(new CaveatLang.BoundCaveat(m("type", "max_uses", "id", "m", "n", n(1), "until", n(5000)), 0, "h"));
        StateStore boom = (key, counter) -> { throw new IllegalStateException("boom"); };
        StateStore silent = (key, counter) -> { throw new IllegalStateException(); };
        assertEquals("max_uses error (fail closed): boom", CaveatLang.reserveMaxUses(boom, mu, 0L).reason);
        assertEquals("max_uses error (fail closed): unknown", CaveatLang.reserveMaxUses(silent, mu, 0L).reason);
        CaveatLang.UsesVerdict one = CaveatLang.reserveMaxUses(new MemoryStateStore(), mu, 0L);
        assertEquals("UsesVerdict{ok, spent=1}", one.toString());
    }

    @Test void deriveCountWithoutFilters() {
        Map<String, Object> d = m("type", "derive", "id", "d1",
            "defs", List.of(m("name", "c", "kind", "count", "window_ms", n(1000))),
            "check", m("op", "gte", "a", m("ref", "c"), "b", m("const", n(0))));
        assertNull(CaveatLang.deriveError(d));
        Map<String, Object> bad = m("type", "derive", "id", "d1", "defs", List.of(), "check", m("ref", n(5)));
        assertEquals("ref names no earlier def", CaveatLang.deriveError(bad));
    }
}
