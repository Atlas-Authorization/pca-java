package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link ArgProvenance}: the recorder, the chain verifier, the decision and the request reader, asserted exactly. */
public class ArgProvenanceRestKillTest {
    static byte[] fill(int b) { byte[] x = new byte[32]; Arrays.fill(x, (byte) b); return x; }

    static final Keys.SuiteKey KEY = Keys.ed25519(Keys.edFromSeed(fill(5)));
    static final String SESSION = Pca.b64(fill(6));

    static ArgProvenance.Recorder rec() { return new ArgProvenance.Recorder("m", "k", KEY, SESSION, () -> 10L); }

    static final Map<String, Object> PIN = rec().pin();
    static final Authorize.Operation OP = Authorize.Operation.of("v", "r", Map.of("a", "x"));

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static Map<String, Object> opMap() { return m("verb", "v", "resource", "r", "params", m("a", "x")); }

    static ArgProvenance.Result run(Object bundle) {
        ArgProvenance.Input in = new ArgProvenance.Input();
        in.bundle = bundle;
        in.operation = opMap();
        in.mediators = list(PIN);
        return ArgProvenance.decide(in);
    }

    // ---- small helpers --------------------------------------------------------------------------------------------------------

    @Test void bundleSessionReadsTheFirstReceipt() {
        assertNull(ArgProvenance.bundleSession(null));
        assertNull(ArgProvenance.bundleSession("bundle"));
        assertNull(ArgProvenance.bundleSession(m()));
        assertNull(ArgProvenance.bundleSession(m("session", "S")));
        assertNull(ArgProvenance.bundleSession(m("receipts", "S")));
        assertNull(ArgProvenance.bundleSession(m("receipts", list())));
        assertNull(ArgProvenance.bundleSession(m("receipts", list(5))));
        assertNull(ArgProvenance.bundleSession(m("receipts", list(m()))));
        assertNull(ArgProvenance.bundleSession(m("receipts", list(m("session", 5)))));
        assertNull(ArgProvenance.bundleSession(m("receipts", list(m("receipts", "S")))));
        assertEquals("S", ArgProvenance.bundleSession(m("receipts", list(m("session", "S")))));
        assertEquals("S", ArgProvenance.bundleSession(m("receipts", list(m("session", "S"), m("session", "T")))));
        assertEquals("", ArgProvenance.bundleSession(m("receipts", list(m("session", "")))));
    }

    @Test void clipHalvesAndKeepsPairs() {
        assertEquals("-", ArgProvenance.clip(""));
        assertEquals("abc", ArgProvenance.clip("abc"));
        assertEquals("a".repeat(256), ArgProvenance.clip("a".repeat(256)));
        assertEquals("a".repeat(150), ArgProvenance.clip("a".repeat(300)));
        assertEquals("a".repeat(257 / 2), ArgProvenance.clip("a".repeat(257)));
        String pair = "😀";
        // the cut lands on a low surrogate: one step back
        assertEquals("a" + pair.repeat(49), ArgProvenance.clip("a" + pair.repeat(100)));
        // the cut lands on a high surrogate: kept as is
        assertEquals(pair.repeat(50), ArgProvenance.clip(pair.repeat(100)));
    }

    @Test void joinRankAndOriginLevel() {
        assertEquals("x", ArgProvenance.join("x", "y"));
        assertEquals("agent", ArgProvenance.join("agent", "trusted"));
        assertEquals("web", ArgProvenance.join("trusted", "web"));
        assertEquals("tool", ArgProvenance.join("tool", "tool"));
        assertEquals("trusted", ArgProvenance.originLevel("principal"));
        assertEquals("tool", ArgProvenance.originLevel("tool"));
        assertEquals("tool", ArgProvenance.originLevel("retrieval"));
        assertEquals("web", ArgProvenance.originLevel("web"));
        assertEquals("agent", ArgProvenance.originLevel("action"));
        assertEquals("agent", ArgProvenance.originLevel(null));
        assertEquals("agent", ArgProvenance.originLevel(5));
    }

    @Test void occursAsTokenNulls() {
        assertFalse(ArgProvenance.occursAsToken(null, "a"));
        assertFalse(ArgProvenance.occursAsToken("a", null));
        assertFalse(ArgProvenance.occursAsToken("a", ""));
        assertFalse(ArgProvenance.occursAsToken(null, null));
        assertTrue(ArgProvenance.occursAsToken("a", "a"));
    }

    @Test void readOnlyNeedsAListOfTraits() {
        assertTrue(ArgProvenance.isReadOnlyAction(m("effects", list("read"))));
        assertTrue(ArgProvenance.isReadOnlyAction(m("effects", list("read"), "traits", list("pca.pii_access"))));
        assertFalse(ArgProvenance.isReadOnlyAction(m("effects", list("read"), "traits", "pca.pii_access")));
        assertFalse(ArgProvenance.isReadOnlyAction(m("effects", list("read"), "traits", m())));
        assertFalse(ArgProvenance.isReadOnlyAction(m("effects", list("read"), "traits", list("pca.money_moving"))));
    }

    @Test void textOfFallsBackToTheJavaText() {
        assertEquals("s", ArgProvenance.textOf("s"));
        assertEquals("[1]", ArgProvenance.textOf(list(1)));
        Object odd = new Object() { @Override public String toString() { return "odd"; } };
        assertEquals("odd", ArgProvenance.textOf(odd));
        assertEquals("[odd]", ArgProvenance.textOf(list(odd)));
    }

    @Test void leavesCountAndNumbers() {
        assertEquals(List.of("1.5"), ArgProvenance.leaves(list(1.5d)));
        assertEquals(List.of("2"), ArgProvenance.leaves(list(2.0d)));
        List<Object> full = new ArrayList<>();
        for (int i = 0; i < ArgProvenance.MAX_LEAVES; i++) full.add("a");
        List<Object> fullThenEmpty = new ArrayList<>(full);
        fullThenEmpty.add(list());
        fullThenEmpty.add(m());
        assertEquals(ArgProvenance.MAX_LEAVES, ArgProvenance.leaves(fullThenEmpty).size());
        List<Object> over = new ArrayList<>(full);
        over.add("b");
        assertNull(ArgProvenance.leaves(over));
        List<Object> keyOver = new ArrayList<>(full);
        keyOver.add(m("k", list()));
        assertNull(ArgProvenance.leaves(keyOver));
        List<Object> nestedOver = new ArrayList<>(full);
        nestedOver.add(list(list("b")));
        assertNull(ArgProvenance.leaves(nestedOver));
    }

    // ---- the decision ---------------------------------------------------------------------------------------------------------

    static ArgProvenance.Input bare() {
        ArgProvenance.Input in = new ArgProvenance.Input();
        in.operation = m("verb", "v", "resource", "r", "params", m());
        return in;
    }

    @Test void defaultInputHasNoPins() {
        ArgProvenance.Result r = ArgProvenance.decide(bare());
        assertEquals("escalate", r.outcome);
        assertEquals("untrusted_control", r.code);
        assertEquals("the choice of v derives from untrusted content [unlabelled]: the principal must confirm (prompt-injection path)", r.reason);
        assertFalse(r.verified);
        assertTrue(r.sensitive);
        assertThrows(UnsupportedOperationException.class, () -> r.labels.put("x", "y"));
    }

    @Test void observationSourceBound() {
        ArgProvenance.Input in = bare();
        in.observed = list(m("origin", "tool", "source", "s".repeat(256)));
        ArgProvenance.Result ok = ArgProvenance.decide(in);
        assertEquals("escalate", ok.outcome);
        assertEquals(List.of("tool:" + "s".repeat(256), "unlabelled"), ok.path);
        in.observed = list(m("origin", "tool", "source", "s".repeat(257)));
        ArgProvenance.Result bad = ArgProvenance.decide(in);
        assertEquals("deny", bad.outcome);
        assertEquals("malformed_config", bad.code);
        assertEquals("observations must be a list of {origin, source}", bad.reason);
    }

    @Test void evaluationErrorNamesTheException() {
        ArgProvenance.Input in = bare();
        in.operation = m("verb", "v", "resource", "r", "params", new LinkedHashMap<String, Object>() {
            @Override public Set<String> keySet() { throw new IllegalStateException("x"); }
        });
        ArgProvenance.Result r = ArgProvenance.decide(in);
        assertEquals("deny", r.outcome);
        assertEquals("malformed_config", r.code);
        assertEquals("evaluation error (fail closed): IllegalStateException", r.reason);
    }

    // ---- the chain ------------------------------------------------------------------------------------------------------------

    @Test void principalContentSizeBound() {
        ArgProvenance.Recorder at = rec();
        at.principal("a".repeat(ArgProvenance.MAX_CONTENT_BYTES));
        ArgProvenance.Result ok = run(at.forAction(OP));
        assertEquals("pass", ok.outcome, ok.reason);
        assertTrue(ok.verified);
        assertEquals("trusted", ok.control);

        ArgProvenance.Recorder over = rec();
        String big = "a".repeat(ArgProvenance.MAX_CONTENT_BYTES + 1);
        over.principal(big);
        Map<String, Object> b = over.forAction(OP);
        assertFalse(b.containsKey("contents"));   // the recorder does not ship it
        b.put("contents", m("0", big));
        ArgProvenance.Result r = run(b);
        assertEquals("deny", r.outcome);
        assertEquals("malformed_bundle", r.code);
        assertEquals("contents '0' must be a string of at most 65536 bytes", r.reason);
    }

    /** Receipts built by hand (any origin / source / digest), signed by the pinned mediator key. */
    static Map<String, Object> bundle(String[]... specs) {
        List<Object> rs = new ArrayList<>();
        Map<String, Object> prev = null;
        for (int i = 0; i < specs.length; i++) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("v", 1L);
            body.put("kind", "pca-prov");
            body.put("mediator", "m");
            body.put("kid", "k");
            body.put("session", SESSION);
            body.put("seq", (long) i);
            body.put("prev", prev == null ? null : ArgProvenance.receiptRef(prev));
            body.put("origin", specs[i][0]);
            body.put("source", specs[i][1]);
            body.put("content_digest", specs[i][2]);
            body.put("issued_at", 10L);
            prev = Issue.signArtifact(ArgProvenance.RECEIPT_DOMAIN, body, KEY);
            rs.add(prev);
        }
        return m("v", 1L, "kind", "pca-provenance", "receipts", rs);
    }

    static final String ACT = ArgProvenance.actionDigest("v", "r", m("a", "x"));
    static final String[] HI = {"principal", "user", Pca.hashCanonical("hi")};

    @Test void theLastReceiptMustBeThisAction() {
        assertEquals("pass", run(bundle(HI, new String[] {"action", "v", ACT})).outcome);
        String unbound = "the last receipt is not the action receipt of this operation";
        for (String[] last : new String[][] {{"web", "v", ACT}, {"tool", "v", ACT}, {"principal", "v", ACT}, {"action", "w", ACT}, {"action", "v", Pca.hashCanonical("other")}}) {
            ArgProvenance.Result r = run(bundle(HI, last));
            assertEquals("deny", r.outcome, last[0] + " " + last[1]);
            assertEquals("unbound_action", r.code);
            assertEquals(unbound, r.reason);
        }
    }

    @Test void labelledOnlyBySegmentsBeforeTheAction() {
        ArgProvenance.Result alone = run(bundle(new String[] {"action", "v", ACT}));
        assertEquals("escalate", alone.outcome);
        assertTrue(alone.verified);
        assertEquals("agent", alone.control);
        assertEquals(List.of("unlabelled"), alone.path);
        // an earlier action receipt labels nothing either
        ArgProvenance.Result twoActions = run(bundle(new String[] {"action", "w", Pca.hashCanonical("w")}, new String[] {"action", "v", ACT}));
        assertEquals("agent", twoActions.control);
        assertEquals(List.of("unlabelled"), twoActions.path);
        String t = Pca.hashCanonical("t");
        ArgProvenance.Result tools = run(bundle(new String[] {"tool", "b", t}, new String[] {"tool", "a", t}, new String[] {"tool", "a", t}, new String[] {"action", "v", ACT}));
        assertTrue(tools.verified);
        assertEquals("tool", tools.control);
        assertEquals(List.of("tool:a", "tool:b"), tools.path);
        ArgProvenance.Result mixed = run(bundle(HI, new String[] {"web", "w.example", t}, new String[] {"action", "v", ACT}));
        assertEquals("web", mixed.control);
        assertEquals(List.of("web:w.example"), mixed.path);
        assertEquals("escalate", mixed.outcome);
        assertEquals("the choice of v derives from untrusted content; a derives from untrusted content [web:w.example]: the principal must confirm (prompt-injection path)", mixed.reason);
    }

    // ---- the recorder ---------------------------------------------------------------------------------------------------------

    @Test void recorderArguments() {
        assertEquals("Recorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required",
            assertThrows(IllegalArgumentException.class, () -> new ArgProvenance.Recorder("", "k", KEY, SESSION, null)).getMessage());
        assertEquals("Recorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required",
            assertThrows(IllegalArgumentException.class, () -> new ArgProvenance.Recorder("m", "k".repeat(65), KEY, SESSION, null)).getMessage());
        assertEquals("Recorder: an Ed25519 (or hybrid) mediator key is required",
            assertThrows(IllegalArgumentException.class, () -> new ArgProvenance.Recorder("m", "k", null, SESSION, null)).getMessage());
        Keys.SuiteKey pure = Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(4)));
        assertEquals("Recorder: an Ed25519 (or hybrid) mediator key is required",
            assertThrows(IllegalArgumentException.class, () -> new ArgProvenance.Recorder("m", "k", pure, SESSION, null)).getMessage());
        assertEquals("Recorder: session must be canonical base64url of 32 bytes",
            assertThrows(IllegalArgumentException.class, () -> new ArgProvenance.Recorder("m", "k", KEY, "short", null)).getMessage());
    }

    @Test void recorderSessionAndPin() {
        assertEquals(SESSION, rec().session());
        ArgProvenance.Recorder a = new ArgProvenance.Recorder("m", "k", KEY, null, null), b = new ArgProvenance.Recorder("m", "k", KEY, null, null);
        assertTrue(IntentArtifacts.isDigest(a.session()));
        assertNotEquals(Pca.b64(new byte[32]), a.session());
        assertNotEquals(a.session(), b.session());
        assertEquals(m("mediator", "m", "kid", "k", "pk", KEY.ed.id()), a.pin());
        assertThrows(UnsupportedOperationException.class, () -> a.pin().put("x", "y"));
    }

    @Test void recorderClockAndSource() {
        long[] t = {0L, 0L, 5L};
        int[] i = {0};
        ArgProvenance.Recorder r = new ArgProvenance.Recorder("m", "k", KEY, SESSION, () -> t[Math.min(i[0]++, 2)]);
        assertEquals(0L, IntentJs.lng(r.principal("x").get("issued_at")));
        Map<String, Object> tool = r.tool(null, "out");
        assertEquals("-", tool.get("source"));
        assertEquals(0L, IntentJs.lng(tool.get("issued_at")));
        assertEquals(5L, IntentJs.lng(r.web("u", "c").get("issued_at")));
        ArgProvenance.Recorder back = new ArgProvenance.Recorder("m", "k", KEY, SESSION, new java.util.function.LongSupplier() {
            long n = 20;
            @Override public long getAsLong() { return n -= 10; }
        });
        assertEquals(10L, IntentJs.lng(back.principal("x").get("issued_at")));
        assertEquals(10L, IntentJs.lng(back.principal("y").get("issued_at")));   // the clock went back to 0: never older
    }

    @Test void recorderCapacity() {
        ArgProvenance.Recorder r = rec();
        for (int k = 0; k < ArgProvenance.MAX_RECEIPTS; k++) r.tool("t", "o");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> r.forAction(OP));
        assertEquals("provenance: the session holds 256 receipts; start a new session with the principal's message", e.getMessage());
        ArgProvenance.Recorder fits = rec();
        for (int k = 0; k < ArgProvenance.MAX_RECEIPTS - 1; k++) fits.tool("t", "o");
        assertEquals(ArgProvenance.MAX_RECEIPTS, ((List<?>) fits.forAction(OP).get("receipts")).size());
    }

    @Test void recorderCopiesNonCanonicalParams() {
        Authorize.Operation op = Authorize.Operation.of("v", "r", Map.of("a", 1.5));
        Map<String, Object> b = rec().forAction(op);
        List<?> rs = (List<?>) b.get("receipts");
        assertEquals(ArgProvenance.actionDigest("v", "r", m("a", new Json.Num("1.5"))), ((Map<?, ?>) rs.get(0)).get("content_digest"));
        Map<String, Object> d = ArgProvenance.principalDirect(rec(), op);
        assertEquals(2, ((List<?>) d.get("receipts")).size());
        assertEquals(m("0", "{\"params\":{\"a\":1.5},\"resource\":\"r\",\"verb\":\"v\"}"), d.get("contents"));
    }

    @Test void optionsDefaults() {
        ArgProvenance.Options o = new ArgProvenance.Options();
        assertEquals(List.of(), o.mediators);
        assertSame(o, o.mediators(null));
        assertEquals(List.of(), o.mediators);
        o.mediators(List.of(PIN));
        assertEquals(List.of(PIN), o.mediators);
        ArgProvenance.Observed obs = (pcactn, op, session) -> null;
        assertSame(o, o.observed(obs));
        assertSame(obs, o.observed);
    }

    // ---- the request side -----------------------------------------------------------------------------------------------------

    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    @Test void requestBundleSources() {
        assertEquals("the PCA-Provenance header is not canonical base64url of UTF-8",
            assertThrows(IllegalArgumentException.class, () -> ArgProvenance.requestBundle("!!!", null)).getMessage());
        assertEquals(m("a", new Json.Num("1")).toString(), String.valueOf(ArgProvenance.requestBundle(Pca.b64(utf8("{\"a\":1}")), null)));
        assertNull(ArgProvenance.requestBundle(null, null));
        assertNull(ArgProvenance.requestBundle("", null));
        assertNull(ArgProvenance.requestBundle(null, new byte[0]));
        assertNull(ArgProvenance.requestBundle(null, new byte[] {(byte) 0xff}));
        assertNull(ArgProvenance.requestBundle(null, utf8("[1]")));
        assertNull(ArgProvenance.requestBundle(null, utf8("null")));
        assertNull(ArgProvenance.requestBundle(null, utf8("\"pca_provenance\"")));
        assertNull(ArgProvenance.requestBundle(null, utf8("{\"x\":1}")));
        assertNull(ArgProvenance.requestBundle(null, utf8("{")));
        assertEquals("b", ArgProvenance.requestBundle(null, utf8("{\"pca_provenance\":\"b\"}")));
        assertEquals("b", ArgProvenance.requestBundle("", utf8("{\"pca_provenance\":\"b\"}")));
    }
}
