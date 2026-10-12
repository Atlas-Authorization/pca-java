package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Depth caps and totality on untrusted / hostile values (R6-05 + the native depth audit). The strict profile caps nesting at
 * {@link Json#MAX_DEPTH} (32, the top-level container is depth 1, as in TS strict-json.ts). Every protocol digest (capHash /
 * hop body digest, Merkle leaves, the signer-set hash) uses the STRICT canonical form, as hash.ts canonicalBytes: before, the
 * JVM hashed hops/leaves under the LENIENT form, so (a) a hop signed over out-of-profile bytes (depth 33, a lone surrogate)
 * verified where the reference refuses it, and (b) a deeply nested caveat / leaf / grant overflowed the JVM stack and the
 * StackOverflowError escaped every "total" entry point (they only catch RuntimeException). The public lenient
 * {@link Json#canonicalize} is capped at {@link Json#MAX_LENIENT_DEPTH}.
 */
public class DepthTotalityTest {
    static Map<String, Object> map(Object... kv) { return PcaUnitTest.map(kv); }

    static final int LENIENT = Json.MAX_LENIENT_DEPTH;

    /** Runs `r` on a thread with a 512 KiB stack (a typical servlet worker), rethrowing anything it throws (incl. Errors). */
    static void onSmallStack(ThrowingRunnable r) throws Throwable {
        Throwable[] box = new Throwable[1];
        Thread t = new Thread(null, () -> { try { r.run(); } catch (Throwable e) { box[0] = e; } }, "small-stack", 512 * 1024);
        t.start();
        t.join();
        if (box[0] != null) throw box[0];
    }
    interface ThrowingRunnable { void run() throws Throwable; }

    /** k nested lists around 1: depth k. */
    static Object nested(int k) {
        Object a = 1;
        for (int i = 0; i < k; i++) { List<Object> l = new ArrayList<>(); l.add(a); a = l; }
        return a;
    }

    @Test void strictParseDepthLimitBoundary() throws Throwable {
        onSmallStack(() -> {
        assertNotNull(Json.parse("[".repeat(31) + "]".repeat(31)));
        assertNotNull(Json.parse("[".repeat(32) + "]".repeat(32)));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(33) + "]".repeat(33))).getMessage().startsWith("nesting too deep"));
        // 100000 levels: refused at level 33 before any further recursion (no StackOverflowError)
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(100000) + "]".repeat(100000))).getMessage().startsWith("nesting too deep"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":".repeat(100000) + "1" + "}".repeat(100000))).getMessage().startsWith("nesting too deep"));
        });
    }

    @Test void lenientCanonicalDepthCap() throws Throwable {
        onSmallStack(() -> {
        assertNotNull(Json.canonicalize(nested(LENIENT - 1)));
        assertNotNull(Json.canonicalize(nested(LENIENT)));
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(nested(LENIENT + 1))).getMessage());
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(nested(100000))).getMessage());
        // a cycle is refused by the same cap (it used to overflow the stack)
        List<Object> cyc = new ArrayList<>();
        cyc.add(cyc);
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(cyc)).getMessage());
        Map<String, Object> cm = new LinkedHashMap<>();
        cm.put("self", cm);
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(cm)).getMessage());
        });
    }

    static String keyPub(String name) throws Exception {
        return (String) PcaUnitTest.m(((Map<?, ?>) ReasonSnapshot.loadJson("keys.json")).get(name)).get("public");
    }

    /** A root capability signed by `principal` over the LENIENT canonical bytes of its body (what a non-reference signer emits). */
    @SuppressWarnings("unchecked")
    static Map<String, Object> leniently(List<Object> caveats) throws Exception {
        Map<String, Object> keys = (Map<String, Object>) ReasonSnapshot.loadJson("keys.json");
        byte[] seed = Pca.decodeB64uStrict(PcaUnitTest.m(keys.get("principal")).get("seed"), 32);
        Map<String, Object> body = map("issuer", keyPub("principal"), "holder", keyPub("agent"), "caveats", caveats, "parent", null);
        String digest = Pca.b64(Pca.sha(Json.canonicalize(body).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        byte[] msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed, 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", digest); c.put("issuer", body.get("issuer")); c.put("holder", body.get("holder")); c.put("caveats", caveats);
        c.put("body_digest", digest); c.put("sig", Pca.b64(sig));
        return c;
    }

    /** A root whose one caveat carries a value nested `k` lists deep (hop depth 3 + k), signed over the lenient bytes. */
    static Map<String, Object> rootWithDepth(int k) throws Exception {
        List<Object> cav = new ArrayList<>();
        cav.add(map("type", "note", "v", nested(k)));
        return leniently(cav);
    }

    @Test void chainHopDepthAroundTheStrictLimit() throws Exception {
        // hop digests are strict (TS capHash = hashCanonical = canonicalizeStrict): hop depth 31 and 32 verify, 33 is refused
        // even though it is validly signed over the (uncapped) lenient bytes
        for (int hopDepth : new int[] {31, 32}) {
            Map<String, Object> r = rootWithDepth(hopDepth - 3);
            assertEquals("", Pca.verifyChain(new ArrayList<>(List.of(r)), (String) r.get("issuer"), true, null), "hop depth " + hopDepth);
        }
        Map<String, Object> r33 = rootWithDepth(30);
        assertEquals("hop 0: malformed body", Pca.verifyChain(new ArrayList<>(List.of(r33)), (String) r33.get("issuer"), true, null));
    }

    @Test void chainHopOutOfProfileIsRefused() throws Exception {
        // a lone surrogate in a caveat: the lenient form hashes it (as U+FFFD), the reference's strict form refuses it
        List<Object> cav = new ArrayList<>();
        cav.add(map("type", "note", "v", "\uD800"));
        Map<String, Object> r = leniently(cav);
        assertEquals("hop 0: malformed body", Pca.verifyChain(new ArrayList<>(List.of(r)), (String) r.get("issuer"), true, null));
        // the same caveat in a Merkle leaf: no inclusion
        String lenientRoot = Pca.b64(Pca.sha(new byte[] {0x00}, Json.canonicalize(map("a", "\uD800")).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertFalse(Pca.verifyInclusion(lenientRoot, map("index", 0, "size", 1, "path", new ArrayList<>()), map("a", "\uD800")));
        assertTrue(Pca.verifyInclusion(Pca.b64(Pca.leafHash(map("a", "x"))), map("index", 0, "size", 1, "path", new ArrayList<>()), map("a", "x")));
    }

    @Test void chainIsTotalOnHostileDepth() throws Throwable {
        onSmallStack(() -> {
        Map<String, Object> r = rootWithDepth(1);
        String issuer = (String) r.get("issuer");
        // 100000-deep caveat value: a refusal, never a StackOverflowError
        Map<String, Object> deep = new LinkedHashMap<>(r);
        List<Object> cav = new ArrayList<>();
        cav.add(map("type", "note", "v", nested(100000)));
        deep.put("caveats", cav);
        String why = Pca.verifyChain(new ArrayList<>(List.of(deep)), issuer, true, null);
        assertEquals("hop 0: malformed body", why);
        // a cyclic caveat: same
        Map<String, Object> cyc = new LinkedHashMap<>(r);
        Map<String, Object> cv = map("type", "note");
        cv.put("self", cv);
        List<Object> cl = new ArrayList<>();
        cl.add(cv);
        cyc.put("caveats", cl);
        assertEquals("hop 0: malformed body", Pca.verifyChain(new ArrayList<>(List.of(cyc)), issuer, true, null));
        // a deep caveat on the PARENT of hop 1 (parent link hashing) is a refusal too
        Map<String, Object> kid = new LinkedHashMap<>(r);
        assertFalse(Pca.verifyChain(new ArrayList<>(List.of(deep, kid)), issuer, false, null).isEmpty());
        });
    }

    @Test void inclusionIsTotalOnHostileDepth() throws Throwable {
        onSmallStack(() -> {
        Map<String, Object> proof = map("index", 0, "size", 1, "path", new ArrayList<>());
        assertFalse(Pca.verifyInclusion("x", proof, nested(100000)));
        });
    }

    @Test void pcactnIsTotalOnHostileGrant() throws Throwable {
        onSmallStack(() -> {
        Map<String, Object> p = PcaUnitTest.valid();
        Map<String, Object> g = new LinkedHashMap<>(PcaUnitTest.validGrant());
        g.put("zz", nested(100000));
        Pca.Verdict v = Pca.verifyPcactn(p, g, 0L, "x");
        assertFalse(v.allow);
        // a 100000-deep PCActn object built by a host parser: a terminal wire refusal
        Map<String, Object> deep = new LinkedHashMap<>(p);
        deep.put("risk_claim", map("r", 0, "inputs", map("x", nested(100000))));
        Pca.Verdict w = Pca.verifyPcactn(deep, PcaUnitTest.validGrant(), 0L, "x");
        assertFalse(w.allow);
        assertFalse(w.checks.get("wire"));
        });
    }

    @Test void pcactnJsonIsTotalOnNullText() {
        // R6-05: a null document is a terminal wire refusal (TS strictParse: 'input is not a string'), never a NullPointerException
        Pca.Verdict v = Pca.verifyPcactnJson(null, new LinkedHashMap<>(), 0L, "x");
        assertFalse(v.allow);
        assertFalse(v.checks.get("wire"));
        assertEquals("wire: strict JSON: input is not a string", v.reason);
    }

    @Test void chainIsTotalOnAThrowingHostMap() {
        // a host-supplied Map implementation that throws: the defence-in-depth catch of verifyChain turns it into a refusal
        Map<String, Object> evil = new LinkedHashMap<>() {
            @Override public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        assertEquals("malformed capability chain: IllegalStateException", Pca.verifyChain(new ArrayList<>(List.of(evil)), "x", true, null));
    }

    @Test void bodyEnvelopeDepthCountsTowardTheCap() {
        // TS defaultExtract strict-parses the WHOLE {"pcactn": ...} body (cap 32): the envelope counts. Total depth 32 parses (and is
        // then refused for having no grant_ref), total depth 33 is undecodable.
        net.atlasauth.pca.servlet.GrantResolver none = ref -> null;
        String d32 = "{\"pcactn\":" + "[".repeat(31) + "]".repeat(31) + "}";
        String d33 = "{\"pcactn\":" + "[".repeat(32) + "]".repeat(32) + "}";
        assertEquals(net.atlasauth.pca.servlet.PcaResult.Outcome.UNKNOWN_GRANT,
            net.atlasauth.pca.servlet.PcaCore.authorize(null, d32.getBytes(java.nio.charset.StandardCharsets.UTF_8), "aud", 0L, none).outcome());
        assertEquals(net.atlasauth.pca.servlet.PcaResult.Outcome.UNDECODABLE,
            net.atlasauth.pca.servlet.PcaCore.authorize(null, d33.getBytes(java.nio.charset.StandardCharsets.UTF_8), "aud", 0L, none).outcome());
    }
}
