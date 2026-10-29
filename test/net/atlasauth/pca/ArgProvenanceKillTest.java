package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/** 0.5 mutation kills (provenance by default): every boundary of {@link ArgProvenance} pinned with literal expectations. */
public class ArgProvenanceKillTest {
    static byte[] fill(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return x;
    }

    static final Keys.SuiteKey KEY = Keys.ed25519(Keys.edFromSeed(fill(5)));
    static final String SESSION = Pca.b64(fill(6));

    static ArgProvenance.Recorder rec() { return new ArgProvenance.Recorder("m", "k", KEY, SESSION, () -> 10L); }

    static final Map<String, Object> PIN = rec().pin();
    static final Authorize.Operation OP = Authorize.Operation.of("v", "r", Map.of("a", "x"));

    static Map<String, Object> op(String verb, String resource, Map<String, Object> params) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("verb", verb);
        m.put("resource", resource);
        m.put("params", params);
        return m;
    }

    static final Map<String, Object> OPM = op("v", "r", Map.of("a", "x"));

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> receipts(Map<String, Object> bundle) { return (List<Object>) bundle.get("receipts"); }

    /** A deep, mutable copy (the recorder's own receipts are never touched). */
    @SuppressWarnings("unchecked")
    static Map<String, Object> clone(Object x) { return (Map<String, Object>) Json.parseLenient(Json.canonicalize(x)); }

    static ArgProvenance.Result decide(Object bundle, Object operation, List<?> pins, Object action, boolean control, Object observed) {
        ArgProvenance.Input in = new ArgProvenance.Input();
        in.bundle = bundle;
        in.operation = operation;
        in.mediators = pins;
        in.action = action;
        in.principalControl = control;
        in.observed = observed;
        return ArgProvenance.decide(in);
    }

    static ArgProvenance.Result decide(Object bundle) { return decide(bundle, OPM, List.of(PIN), null, false, null); }

    static Map<String, Object> principalOnly() {
        ArgProvenance.Recorder r = rec();
        r.principal("x");
        return r.forAction(OP);
    }

    @Test void pinsEveryWireConstant() {
        assertEquals(List.of("atlas-pca/prov-receipt/v1\0", "atlas-pca/prov-receipt-ref/v1", "atlas-pca/prov-action/v1", "PCA-Provenance", "pca_provenance"),
            List.of(ArgProvenance.RECEIPT_DOMAIN, ArgProvenance.RECEIPT_REF_DOMAIN, ArgProvenance.ACTION_DOMAIN, ArgProvenance.HEADER, ArgProvenance.BODY_MEMBER));
        assertEquals(List.of(256, 65536, 4096, 16),
            List.of(ArgProvenance.MAX_RECEIPTS, ArgProvenance.MAX_CONTENT_BYTES, ArgProvenance.MAX_LEAVES, ArgProvenance.MAX_ENVELOPE_MEDIATORS));
        assertEquals(List.of("principal", "tool", "retrieval", "web", "action"), ArgProvenance.ORIGINS);
        assertEquals(List.of("trusted", "first_party", "tool", "web", "agent"), ArgProvenance.LEVELS);
        assertEquals(List.of("pca.financial_data_read", "pca.pii_access", "pca.regulated_data"), ArgProvenance.READ_SAFE_TRAITS);
    }

    // ---- the token boundary ---------------------------------------------------------------------------------------------

    @Test void tokenBoundaryAtEveryWordCharacterRangeEdge() {
        // each pair: a character just outside a word range (a boundary) and just inside (no boundary); non-ASCII is a word character
        Object[][] edges = {
            {"/", true}, {"0", false}, {"9", false}, {":", true}, {"@", true}, {"A", false}, {"Z", false}, {"[", true},
            {"`", true}, {"a", false}, {"z", false}, {"{", true}, {"_", false}, {"^", true}, {"\u007f", true}, {"\u0080", false},
            {"é", false}, {"中", false},
        };
        for (Object[] e : edges) {
            String c = (String) e[0];
            assertEquals(e[1], ArgProvenance.occursAsToken(c + "x", "x"), "'" + c + "' before the needle");
            assertEquals(e[1], ArgProvenance.occursAsToken("x" + c, "x"), "'" + c + "' after the needle");
        }
        assertTrue(ArgProvenance.occursAsToken("a.b", ".b"));
        assertFalse(ArgProvenance.occursAsToken("a.bc", ".b"));
        assertFalse(ArgProvenance.occursAsToken("ab.", "b."));
        assertTrue(ArgProvenance.occursAsToken(" b.", "b."));
        assertTrue(ArgProvenance.occursAsToken("pay été now", "été"));
        assertFalse(ArgProvenance.occursAsToken("pay xété now", "été"));
    }

    @Test void leavesDepthAndCountLimits() {
        Object nest32 = "x", nest33;
        for (int i = 0; i < 32; i++) nest32 = List.of(nest32);
        nest33 = List.of(nest32);
        assertEquals(List.of("x"), ArgProvenance.leaves(nest32));
        assertNull(ArgProvenance.leaves(nest33));
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < 2048; i++) o.put("k" + i, "v");
        assertEquals(4096, ArgProvenance.leaves(o).size()); // keys count as leaves
        o.put("extra", "v");
        assertNull(ArgProvenance.leaves(o));
    }

    // ---- wire bounds ----------------------------------------------------------------------------------------------------

    @Test void receiptStringBoundsAreByteLengths() {
        Map<String, Object> r = rec().principal("p");
        java.util.function.BiFunction<String, Object, String> with = (k, v) -> {
            Map<String, Object> c = clone(r);
            c.put(k, v);
            return ArgProvenance.receiptWireError(c);
        };
        assertNull(ArgProvenance.receiptWireError(r));
        assertNull(with.apply("mediator", "m".repeat(256)));
        assertTrue(with.apply("mediator", "m".repeat(257)).contains("mediator"));
        assertTrue(with.apply("mediator", "é".repeat(129)).contains("mediator")); // 258 bytes, 129 characters
        assertNull(with.apply("kid", "k".repeat(64)));
        assertTrue(with.apply("kid", "k".repeat(65)).contains("kid"));
        assertTrue(with.apply("source", "s".repeat(257)).contains("source"));
        assertNull(with.apply("issued_at", 0L));
        assertTrue(with.apply("issued_at", -1L).contains("issued_at"));
        assertNotNull(with.apply("v", 2L));
        assertNotNull(with.apply("session", "x"));
        assertTrue(with.apply("content_digest", "x").contains("content_digest"));
    }

    @Test void actionInfoAndPinBounds() {
        List<String> e64 = new ArrayList<>(), e65 = new ArrayList<>();
        for (int i = 0; i < 64; i++) e64.add("e");
        e65.addAll(e64);
        e65.add("e");
        assertNull(ArgProvenance.actionInfoError(Map.of("effects", e64)));
        assertNotNull(ArgProvenance.actionInfoError(Map.of("effects", e65)));
        assertNull(ArgProvenance.actionInfoError(Map.of("traits", List.of("t".repeat(128)))));
        assertNotNull(ArgProvenance.actionInfoError(Map.of("traits", List.of("t".repeat(129)))));
        assertNotNull(ArgProvenance.actionInfoError(Map.of("params", List.of())));
        assertNotNull(ArgProvenance.actionInfoError(null));
        Map<String, Object> pq = new LinkedHashMap<>(PIN);
        pq.put("pq_pk", "");
        assertFalse(ArgProvenance.isMediatorPin(pq));
        Map<String, Object> noKid = new LinkedHashMap<>(PIN);
        noKid.put("kid", "");
        assertFalse(ArgProvenance.isMediatorPin(noKid));
        List<Object> sixteen = new ArrayList<>();
        for (int i = 0; i < 16; i++) sixteen.add(PIN);
        assertNull(ArgProvenance.envelopeError(Map.of("mediators", sixteen)));
        sixteen.add(PIN);
        assertNotNull(ArgProvenance.envelopeError(Map.of("mediators", sixteen)));
        assertNull(ArgProvenance.envelopeError(Map.of("mode", "enforce")));
        assertNull(ArgProvenance.envelopeError(Map.of("mode", "insecure_off")));
        assertNotNull(ArgProvenance.envelopeError(Map.of("mode", "off")));
        assertNotNull(ArgProvenance.envelopeError(Map.of("mediators", List.of(Map.of()))));
        assertNotNull(ArgProvenance.envelopeError(null));
    }

    // ---- the decision ---------------------------------------------------------------------------------------------------

    @Test void theRecorderRoundTripsAndEveryReceiptVerifies() {
        ArgProvenance.Recorder r = rec();
        r.principal("send x");
        r.tool("t", Map.of("y", 1L));
        r.retrieval("doc", "z");
        r.web("https://w.example", "w");
        Map<String, Object> b = r.forAction(OP);
        assertEquals(5, receipts(b).size());
        assertEquals(r.receipts(), receipts(b));
        for (Object x : receipts(b)) assertNull(ArgProvenance.receiptWireError(x));
        assertEquals(Map.of("0", "send x"), b.get("contents"));
        ArgProvenance.Result d = decide(clone(b), OPM, List.of(PIN), null, true, null);
        assertTrue(d.verified, d.reason);
        assertEquals(List.of("retrieval:doc", "tool:t", "web:https://w.example"), d.path);
    }

    @Test void receiptsVerifyUnderTheReferenceByteForByte() throws Exception {
        // the principal-direct decision vector: key seed and session are derived from fixed labels, the clock is fixed
        Map<String, Object> doc = Track3Vectors.load("arg-provenance-vectors.json");
        Map<String, Object> want = null;
        for (Object o : (List<?>) doc.get("decisions")) if ("principal-direct".equals(m(o).get("name"))) want = m(m(m(o).get("input")).get("bundle"));
        assertNotNull(want, "the principal-direct vector");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] seed = sha.digest("atlas-pca-conformance/arg-provenance/key/harness".getBytes(StandardCharsets.UTF_8));
        String session = Pca.b64(sha.digest("atlas-pca-conformance/arg-provenance/session/harness".getBytes(StandardCharsets.UTF_8)));
        ArgProvenance.Recorder r = new ArgProvenance.Recorder("assistant-harness", "k1", Keys.ed25519(Keys.edFromSeed(seed)), session, () -> 1793188800000L);
        assertTrue(IntentJs.jsonEquals(doc.get("pin"), r.pin()), "the harness pin");
        Map<String, Object> got = ArgProvenance.principalDirect(r,
            Authorize.Operation.of("payments.send", "bank", Map.of("iban", "DE89370400440532013000", "amount", 120L)));
        assertTrue(IntentJs.jsonEquals(want, got), "want " + want + ", got " + got);
        assertEquals(Json.canonicalize(want), Json.canonicalize(got));
    }

    @Test void a256ReceiptChainPasses() {
        ArgProvenance.Recorder r = rec();
        for (int i = 0; i < ArgProvenance.MAX_RECEIPTS - 1; i++) r.principal("x");
        Map<String, Object> b = r.forAction(OP);
        assertEquals(256, receipts(b).size());
        assertEquals("pass", decide(b).outcome);
    }

    @Test void issuedAtIsNonDecreasing() {
        AtomicLong t = new AtomicLong(10);
        ArgProvenance.Recorder r = new ArgProvenance.Recorder("m", "k", KEY, SESSION, () -> t.getAndAdd(10));
        r.principal("x");
        Map<String, Object> b = r.forAction(OP); // 10, 20: increasing
        assertEquals("pass", decide(b).outcome);
        Map<String, Object> eq = principalOnly(); // 10, 10: equal is fine
        assertTrue(IntentJs.jsonEquals(m(receipts(eq).get(0)).get("issued_at"), m(receipts(eq).get(1)).get("issued_at")));
        assertEquals("pass", decide(eq).outcome);
        Map<String, Object> older = clone(b);
        m(receipts(older).get(1)).put("issued_at", 9L); // older than its predecessor
        ArgProvenance.Result d = decide(older);
        assertEquals("broken_chain", d.code);
        assertEquals("receipt 1 is older than its predecessor", d.reason);
    }

    @Test void seqZeroMustHavePrevNullAndSeqMustBeContiguous() {
        Map<String, Object> b = clone(principalOnly());
        m(receipts(b).get(0)).put("prev", m(receipts(b).get(0)).get("content_digest"));
        assertEquals("broken_chain", decide(b).code);
        Map<String, Object> gap = clone(principalOnly());
        m(receipts(gap).get(1)).put("seq", 2L);
        ArgProvenance.Result d = decide(gap);
        assertEquals("broken_chain", d.code);
        assertEquals("receipt 1 has seq 2", d.reason);
    }

    @Test void theLastReceiptBindsVerbResourceAndParams() {
        Map<String, Object> b = principalOnly();
        assertEquals("pass", decide(b).outcome);
        for (Map<String, Object> other : List.of(op("w", "r", Map.of("a", "x")), op("v", "s", Map.of("a", "x")), op("v", "r", Map.of("a", "y")),
            op("v", "r", Map.of("a", "x", "b", "x")))) {
            ArgProvenance.Result d = decide(b, other, List.of(PIN), null, false, null);
            assertEquals("unbound_action", d.code, "operation " + other);
            assertEquals("the last receipt is not the action receipt of this operation", d.reason);
        }
    }

    @Test void aPinMatchesOnMediatorAndKidAndTheFirstMatchIsUsed() {
        Map<String, Object> b = principalOnly();
        assertTrue(decide(b).verified);
        Map<String, Object> otherKid = new LinkedHashMap<>(PIN), otherMediator = new LinkedHashMap<>(PIN), zeroKey = new LinkedHashMap<>(PIN);
        otherKid.put("kid", "k2");
        otherMediator.put("mediator", "m2");
        zeroKey.put("pk", Pca.b64(new byte[32]));
        for (Map<String, Object> pin : List.of(otherKid, otherMediator)) {
            ArgProvenance.Result d = decide(b, OPM, List.of(pin), null, false, null);
            assertFalse(d.verified, "pin " + pin);
            assertEquals("escalate", d.outcome);
            assertEquals(List.of("unlabelled"), d.path);
        }
        assertEquals("bad_signature", decide(b, OPM, List.of(zeroKey, PIN), null, false, null).code);
        assertTrue(decide(b, OPM, List.of(otherKid, PIN), null, false, null).verified);
    }

    @Test void anObservedToolRaisesTheTrustedContext() {
        Map<String, Object> b = principalOnly(); // a principal-only context is trusted: the choice is the principal's
        ArgProvenance.Result clean = decide(b);
        assertEquals("pass", clean.outcome);
        assertEquals("trusted", clean.control);
        ArgProvenance.Result seen = decide(b, OPM, List.of(PIN), null, false, List.of(Map.of("origin", "tool", "source", "t")));
        assertEquals("escalate", seen.outcome);
        assertEquals("tool", seen.control);
        assertEquals(List.of("tool:t"), seen.path);
        // "x" still occurs as a token in the verified principal content: only the choice is untrusted
        assertEquals("untrusted_control", seen.code);
        assertEquals(List.of(), seen.tainted);
    }

    @Test void theFloorOfAnUndeclaredParameter() {
        ArgProvenance.Recorder r = rec();
        r.tool("t", "x");
        Map<String, Object> b = r.forAction(OP);
        java.util.function.Function<Map<String, Object>, List<String>> tainted = a -> decide(b, OPM, List.of(PIN), a, true, null).tainted;
        assertEquals(List.of(), tainted.apply(Map.of("effects", List.of("read"))));            // non-sensitive: agent floor
        assertEquals(List.of("a"), tainted.apply(Map.of("effects", List.of("read"), "params", Map.of("a", "first_party"))));
        assertEquals(List.of("a"), tainted.apply(Map.of("effects", List.of("send"))));         // sensitive: first_party floor
        assertEquals(List.of(), tainted.apply(Map.of("effects", List.of("send"), "params", Map.of("a", "tool"))));
        assertEquals(List.of("a"), tainted.apply(Map.of("effects", List.of("send"), "params", Map.of("b", "agent"))));
    }

    @Test void aReadOnlyActionNeverEscalatesOnControlAlone() {
        ArgProvenance.Result d = decide(null, op("v", "r", Map.of()), List.of(PIN), Map.of("effects", List.of("read")), false, null);
        assertEquals("pass", d.outcome);
        assertFalse(d.sensitive);
        assertEquals("agent", d.control);
    }

    @Test void escalateReasonsAreExact() {
        ArgProvenance.Recorder r = rec();
        r.tool("t", "x");
        Map<String, Object> two = op("v", "r", Map.of("a", "x", "b", "y"));
        assertEquals("a, b derive from untrusted content [tool:t]: the principal must confirm (prompt-injection path)",
            decide(r.forAction(Authorize.Operation.of("v", "r", Map.of("a", "x", "b", "y"))), two, List.of(PIN), null, true, null).reason);
        ArgProvenance.Recorder r2 = rec();
        r2.tool("t", "x");
        assertEquals("a derives from untrusted content [tool:t]: the principal must confirm (prompt-injection path)",
            decide(r2.forAction(OP), OPM, List.of(PIN), null, true, null).reason);
    }

    @Test void aVerbatimMatchNeedsTheStoredPrincipalContent() {
        ArgProvenance.Recorder r = rec();
        r.principal("send x");
        r.tool("t", "y");
        Map<String, Object> b = r.forAction(OP);
        assertEquals("pass", decide(b, OPM, List.of(PIN), null, true, null).outcome);
        Map<String, Object> noContents = clone(b);
        noContents.remove("contents");
        assertEquals(List.of("a"), decide(noContents, OPM, List.of(PIN), null, true, null).tainted);
    }

    @Test void aHybridPostQuantumReceiptVerifiesUnderItsPqPin() {
        Keys.SuiteKey hybrid = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(7)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(8)));
        ArgProvenance.Recorder r = new ArgProvenance.Recorder("m", "k", hybrid, SESSION, () -> 10L);
        assertNotNull(r.pin().get("pq_pk"), "a hybrid recorder pins its post-quantum key");
        r.principal("x");
        Map<String, Object> b = r.forAction(OP);
        for (Object x : receipts(b)) {
            assertEquals("hybrid-ed25519-ml-dsa-65", m(x).get("alg"));
            assertNull(ArgProvenance.receiptWireError(x));
        }
        ArgProvenance.Result ok = decide(b, OPM, List.of(r.pin()), null, false, null);
        assertEquals("pass", ok.outcome, ok.reason);
        assertTrue(ok.verified);
        Map<String, Object> wrongPq = new LinkedHashMap<>(r.pin());
        wrongPq.put("pq_pk", Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(7)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(9))).pqPk());
        assertEquals("bad_signature", decide(b, OPM, List.of(wrongPq), null, false, null).code);
        // the post-quantum half is bound: a stripped pq_sig no longer verifies
        Map<String, Object> stripped = clone(b);
        m(receipts(stripped).get(0)).remove("pq_sig");
        assertEquals("deny", decide(stripped, OPM, List.of(r.pin()), null, false, null).outcome);
    }

    @Test void requestBundleReadsTheHeaderThenTheBody() {
        Map<String, Object> b = principalOnly();
        String header = Pca.b64(Json.canonicalizeStrict(b).getBytes(StandardCharsets.UTF_8));
        assertTrue(IntentJs.jsonEquals(b, ArgProvenance.requestBundle(header, null)));
        byte[] body = Json.canonicalizeStrict(Map.of("pca_provenance", b)).getBytes(StandardCharsets.UTF_8);
        assertTrue(IntentJs.jsonEquals(b, ArgProvenance.requestBundle(null, body)));
        assertTrue(IntentJs.jsonEquals(b, ArgProvenance.requestBundle(header, "{\"pca_provenance\":1}".getBytes(StandardCharsets.UTF_8))), "the header wins");
        assertNull(ArgProvenance.requestBundle(null, "not json".getBytes(StandardCharsets.UTF_8)));
        assertNull(ArgProvenance.requestBundle(null, null));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> ArgProvenance.requestBundle(header + "=", null));
        org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class, () -> ArgProvenance.requestBundle(Pca.b64("{".getBytes(StandardCharsets.UTF_8)), null));
    }
}
