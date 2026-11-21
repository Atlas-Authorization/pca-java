package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.junit.jupiter.api.Test;

/**
 * 0.5 round 3 mutation kills across the smaller classes. Each case pins the reference named beside it. Where the answer alone
 * cannot differ (a bound on the work done before a refusal), a trap in the input observes the early exit.
 */
public class K05R3RestKillTest {
    static Object j(String s) { return Json.parseLenient(s); }
    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static String rep(int len) { return "x".repeat(len); }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    static byte[] filled(int b) {
        byte[] out = new byte[32];
        Arrays.fill(out, (byte) b);
        return out;
    }

    /** A signature of domain || strict-canonical(body) under the Ed25519 key of seed {@code fill}. */
    static String sign(int fill, String domain, Map<String, Object> body) {
        return Keys.b64u(Keys.edFromSeed(filled(fill)).sign(Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body))));
    }

    static String id(int fill) { return Keys.edFromSeed(filled(fill)).id(); }

    /** The given members; reading {@code forbidden} fails the test (an AssertionError is not a RuntimeException: nothing catches it). */
    static Map<String, Object> trap(String forbidden, Object... kv) {
        Map<String, Object> o = new LinkedHashMap<String, Object>() {
            @Override public Object get(Object k) {
                if (forbidden.equals(k)) throw new AssertionError("'" + forbidden + "' was read");
                return super.get(k);
            }
        };
        o.putAll(m(kv));
        return o;
    }

    // ---- ProvenanceGate.verifyRfc9162Inclusion (provenance-gate.ts:57-60)

    @Test void inclusionRefusesNodesThatAreNot32Bytes() {
        byte[] leaf = filled(1), p = filled(2), short31 = new byte[31];
        assertTrue(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 2, Collections.singletonList(p), Pca.nodeHash(leaf, p)), "control");
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(short31, 0, 2, Collections.singletonList(p), Pca.nodeHash(short31, p)), "a 31-byte leaf hash");
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 2, Collections.singletonList(short31), Pca.nodeHash(leaf, short31)), "a 31-byte proof node");
    }

    /** A proof node past the root (provenance-gate.ts:64): the extra hash would otherwise reach a root the attacker picked. */
    @Test void inclusionRefusesANodePastTheRoot() {
        byte[] leaf = filled(1), p = filled(2);
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(leaf, 0, 1, Collections.singletonList(p), Pca.nodeHash(p, leaf)));
    }

    // ---- Ledger: consistency (ledger.ts:136-141)

    @Test void aMissingNewRootNeverPassesTheVacuousCase() {
        Map<String, Object> proof = K05LedgerDiffTest.proof(0, 5);
        assertTrue(Ledger.verifyLedgerConsistency(Ledger.EMPTY_TREE_ROOT, Pca.b64(filled(9)), proof), "control: vacuous for a non-empty new tree");
        assertFalse(Ledger.verifyLedgerConsistency(Ledger.EMPTY_TREE_ROOT, null, proof));
    }

    /** MAX_CONSISTENCY_PATH = 108 (ledger.ts:117): 109 is refused unread, 108 is walked. */
    @Test void aConsistencyPathOverTheCapIsRefusedUnread() {
        Map<String, Object> proof = K05LedgerDiffTest.proof(3, 7);
        proof.put("path", K05ResourceBoundsTest.untouchable(109));
        assertFalse(Ledger.verifyLedgerConsistency(Pca.b64(filled(1)), Pca.b64(filled(2)), proof));
        proof.put("path", K05ResourceBoundsTest.untouchable(108));
        assertThrows(AssertionError.class, () -> Ledger.verifyLedgerConsistency(Pca.b64(filled(1)), Pca.b64(filled(2)), proof));
    }

    // ---- Ledger.jsEq: === compares an array by reference (ledger.ts:631)

    @Test void anArrayEqualsNothing() {
        assertFalse(Ledger.jsEq(List.of("a"), List.of("a")));
        assertFalse(Ledger.jsEq(m("a", 1L), m("a", 1L)));
    }

    // ---- Ledger: witnesses and heads

    static final int GUARDIAN = 101, W1 = 102, W2 = 103;

    /** A head signed by GUARDIAN. */
    static Map<String, Object> head(long size, String root) {
        Map<String, Object> body = m("instance_id", "ins1", "principal", "alice", "size", n(size), "root", root, "prev_root", Ledger.EMPTY_TREE_ROOT, "timestamp", n(1));
        Map<String, Object> h = new LinkedHashMap<>(body);
        h.put("guardian", id(GUARDIAN));
        h.put("sig", sign(GUARDIAN, Ledger.STH_DOMAIN, body));
        return h;
    }

    /** A cosignature of {@code sth} under witness key {@code fill}. */
    static Map<String, Object> cosig(Map<String, Object> sth, int fill) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : new String[] {"instance_id", "principal", "size", "root", "prev_root"}) body.put(k, sth.get(k));
        body.put("guardian_epoch", 0L);
        return m("key", id(fill), "sig", sign(fill, Ledger.STH_WITNESS_DOMAIN, body));
    }

    static Map<String, Object> policy(long threshold, String... keys) {
        return m("threshold", n(threshold), "witnessKeys", new ArrayList<Object>(Arrays.asList((Object[]) keys)));
    }

    /** ledger.ts verifyWitnessCosignature: a missing head or cosignature answers false, it never throws. */
    @Test void aCosignatureCheckNeverThrowsOnAMissingObject() {
        Map<String, Object> sth = head(5, Ledger.EMPTY_TREE_ROOT);
        Map<String, Object> c = cosig(sth, W1);
        assertTrue(Ledger.verifyWitnessCosignature(sth, c, id(W1)), "control");
        assertFalse(Ledger.verifyWitnessCosignature(null, c, id(W1)));
        assertFalse(Ledger.verifyWitnessCosignature(sth, null, id(W1)));
    }

    /** ledger.ts:539: no trusted key answers before the head's witnesses are read. */
    @Test void noTrustedKeyNeverReadsTheWitnesses() {
        Map<String, Object> sth = head(5, Ledger.EMPTY_TREE_ROOT);
        sth.put("witnesses", K05ResourceBoundsTest.untouchable(1));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, policy(1)));
    }

    /** ledger.ts:544-545: the shape and the distinct-trusted checks come before any signature work ('alg' is read only by it). */
    @Test void onlyAFreshTrustedWellShapedCosignatureIsVerified() {
        Map<String, Object> sth = head(5, Ledger.EMPTY_TREE_ROOT);
        Map<String, Object> good = cosig(sth, W1);
        sth.put("witnesses", new ArrayList<Object>(List.of(good)));
        assertTrue(Ledger.verifyWitnessCosignatures(sth, policy(1, id(W1), id(W2))), "control");

        // a duplicate of a key already counted
        sth.put("witnesses", new ArrayList<Object>(List.of(good, trap("alg", "key", id(W1), "sig", good.get("sig")))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, policy(2, id(W1), id(W2))));
        // a trusted key without a signature
        sth.put("witnesses", new ArrayList<Object>(List.of(trap("alg", "key", id(W1)))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, policy(1, id(W1), id(W2))));
        // no key: the signature is not even looked at
        sth.put("witnesses", new ArrayList<Object>(List.of(trap("sig"))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, policy(1, id(W1), id(W2))));
    }

    /** ledger.ts verifyHeadConsistency: the proof must connect exactly the heads' sizes, and a missing size is false, not a throw. */
    @Test void aHeadConsistencyProofNamesExactlyTheHeadsSizes() {
        String any = Pca.b64(filled(9));
        Map<String, Object> older = head(0, Ledger.EMPTY_TREE_ROOT), newer = head(5, any);
        assertTrue(Ledger.verifyHeadConsistency(older, newer, K05LedgerDiffTest.proof(0, 5), id(GUARDIAN), null), "control: the heads verify, the empty old tree is vacuous");
        // the proof's own sizes verify (old size 0, a non-empty new tree): only the comparison with the heads refuses them
        assertFalse(Ledger.verifyHeadConsistency(older, newer, K05LedgerDiffTest.proof(0, 9), id(GUARDIAN), null), "new size differs");
        assertFalse(Ledger.verifyHeadConsistency(head(3, Ledger.EMPTY_TREE_ROOT), newer, K05LedgerDiffTest.proof(0, 5), id(GUARDIAN), null), "old size differs");
        Map<String, Object> noOld = K05LedgerDiffTest.proof(0, 5), noNew = K05LedgerDiffTest.proof(0, 5);
        noOld.remove("oldSize");
        noNew.remove("newSize");
        assertFalse(Ledger.verifyHeadConsistency(older, newer, noOld, id(GUARDIAN), null), "no old size");
        assertFalse(Ledger.verifyHeadConsistency(older, newer, noNew, id(GUARDIAN), null), "no new size");
    }

    // ---- Predicates.denialReason (predicates.ts:695-698): no context reads as undefined, it never throws

    @Test void aDenialWithoutAContextNamesUndefined() {
        assertEquals("no predicate permits undefined on undefined", Predicates.denialReason(j("[{\"verb\":\"pay\"}]"), null));
    }

    // ---- Operations (server/operations.ts:434): only a sole failing replay is answered from the record

    @Test void aDenialWithNoFailingCheckIsDeniedByTheExecutor() {
        Map<String, Object> grant = AuthorizeK05KillTest.GRANT;
        Authorize.Options az = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options());
        Operations.Executor ex = Operations.createExecutor(new Operations.ExecutorOptions().operations(new MemoryOperationStore()).authorize(az)
            .audience(AuthorizeK05KillTest.AUD).resolveGrant(ref -> ref.equals(grant.get("id")) ? grant : null).now(() -> AuthorizeK05KillTest.NOW));
        Authorize.Operation op = Authorize.Operation.of("payments.send", "payments/acme", Issue.obj("amount", 50L));
        // an unsupported bond denies with no check failed
        Operations.ExecuteOutcome out = ex.execute(K05ParityAuditTest.agentSigned("bond_ref", "b"), op, OperationsKillTest.NEVER);
        assertEquals("denied", out.status, out.toString());
        assertEquals("unsupported", out.authorization.checks.get("bond"));
        assertEquals(List.of(), out.authorization.failed());
    }

    // ---- Approval.render (a high surrogate before anything but a low one is lone: ApprovalRestKillTest covers the other shapes)

    @Test void aHighSurrogateBeforeAnotherCharacterIsLone() throws Exception {
        Map<String, Object> p = ApprovalRestKillTest.base();
        p.put("payee", (char) 0xD800 + "a");
        ApprovalRestKillTest.refuses("render_bad_value", "'payee' is not a string in the canonical domain (no floats, no null, no lone surrogates)", ApprovalRestKillTest.def(), p);
    }

    // ---- Optimistic.settlementWireCheck (bond-settlement.ts:434)

    static final String SLASH_HEAD = "{\"claimId\":\"c\",\"action\":\"slash\",\"amount\":10,\"from\":\"a\",\"to\":\"t\",\"at\":1,\"evidenceDigest\":\"e\",\"sig\":\"x\","
        + "\"split\":{\"amount\":10,\"challengerReward\":0,\"victimCompensation\":0,\"treasuryRemainder\":10,\"victimAccount\":\"v\",\"treasuryAccount\":\"t\"";

    /** Only an explicit null is an anonymous challenge: an absent account is no account. */
    @Test void anAbsentChallengerAccountIsNotAnonymous() {
        assertEquals("signature", Optimistic.settlementWireCheck(j(SLASH_HEAD + ",\"challengerAccount\":null}}"), "g"), "control: the split conserves");
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH_HEAD + "}}"), "g"));
    }

    /** Exactly sig and pq_sig leave the signed body: any other member, even one no JSON can spell, stays and fails canonicalization. */
    @Test void onlyTheTwoSignatureMembersLeaveTheSignedBody() {
        Map<String, Object> r = new LinkedHashMap<>(m("claimId", "c", "action", "open", "amount", n(10), "from", "a", "to", "t", "at", n(1), "evidenceDigest", "", "sig", "x"));
        assertEquals("signature", Optimistic.settlementWireCheck(r, "g"), "control");
        r.put(null, "y");
        assertEquals("malformed", Optimistic.settlementWireCheck(r, "g"));
    }

    // ---- IntentHistory (intent-history.ts:61-64, 88-108): what the reference throws

    static void refused(String message, Throwable t) {
        assertEquals(IllegalArgumentException.class, t.getClass(), String.valueOf(t));
        assertEquals(message, t.getMessage());
    }

    static Throwable preStateThrows(Map<String, Object> a, List<?> history, Map<String, Object> cand, Object t) throws Exception {
        Method pre = IntentHistory.class.getDeclaredMethod("preState", Map.class, List.class, Map.class, Object.class, Object.class);
        pre.setAccessible(true); // accPreState folds every throw into null, so the throw is only visible here
        return assertThrows(InvocationTargetException.class, () -> pre.invoke(null, a, history, cand, t, null)).getCause();
    }

    @Test void inWindowWithoutAWindowThrows() {
        refused("inWindow: no window", assertThrows(IllegalArgumentException.class, () -> IntentHistory.inWindow(null, n(1), n(2))));
    }

    @Test void preStateThrowsWhereTheReferenceThrows() throws Exception {
        Map<String, Object> sum = m("agg", "sum", "val", "action.params.x", "sel", m("verbs", List.of("pay")), "win", m("kind", "task"));
        Map<String, Object> keyed = new LinkedHashMap<>(sum);
        keyed.put("key", "action.params.k");
        refused("accPreState: the key parameter action.params.k is missing", preStateThrows(keyed, List.of(), m(), n(10)));
        refused("accPreState: the candidate time is not a safe integer", preStateThrows(sum, List.of(), m(), "x"));
        refused("a history event is null", preStateThrows(sum, Collections.singletonList(null), m(), n(10)));
        refused("accPreState: event e1: the time is not a safe integer", preStateThrows(sum, List.of(m("id", "e1", "status", "committed", "t", "x")), m(), n(10)));
        refused("accPreState: event e1: action.params.x must be a non-negative safe integer",
            preStateThrows(sum, List.of(m("id", "e1", "status", "committed", "t", n(5), "verb", "pay", "params", m("x", "bad"))), m(), n(10)));
        refused("accPreState: sum exceeds 2^53-1", preStateThrows(sum, List.of(
            m("status", "committed", "t", n(5), "verb", "pay", "params", m("x", n(9007199254740991L))),
            m("status", "committed", "t", n(6), "verb", "pay", "params", m("x", n(1)))), m(), n(10)));
    }

    // ---- Lease (pca-grants/src/lease.ts:64, 103, 262-263)

    static Map<String, Object> wellFormedLease() {
        return m("v", n(1), "lease_id", "l", "path", "db/prod", "grant_ref", "g", "holder", "h", "requester", "r", "approvers", new ArrayList<Object>(List.of("ap")),
            "justification_digest", "j", "seq", n(1), "issued_at", n(1000), "renewed_at", n(1000), "expires_at", n(2000), "max_ttl", n(100000), "authority", "a");
    }

    @Test void leaseMembersAreCappedAt128() {
        for (String k : new String[] {"authority", "justification_digest"}) {
            Map<String, Object> l = wellFormedLease();
            l.put(k, rep(128));
            assertTrue(Lease.wellFormed(l), k);
            l.put(k, rep(129));
            assertFalse(Lease.wellFormed(l), k);
        }
        Map<String, Object> rv = m("v", n(1), "target", "lease", "value", "l", "revoked_at", n(1), "authority", rep(128));
        assertTrue(Lease.revocationWellFormed(rv));
        rv.put("authority", rep(129));
        assertFalse(Lease.revocationWellFormed(rv));
    }

    static final int AUTHORITY = 110, REVIEWER = 111;
    static final String[] LEASE_BODY = {"v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority"};

    static Map<String, Object> lease(long seq, long renewed, long expires, String digest) {
        Map<String, Object> l = wellFormedLease();
        l.put("seq", n(seq));
        l.put("renewed_at", n(renewed));
        l.put("expires_at", n(expires));
        l.put("justification_digest", digest);
        l.put("authority", id(AUTHORITY));
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : LEASE_BODY) body.put(k, l.get(k));
        l.put("sig", sign(AUTHORITY, Lease.DOMAIN, body));
        return l;
    }

    @Test void aRenewalMayNeverMoveTimeBackwards() {
        Lease.Registry reg = new Lease.Registry(new Lease.Policy(List.of(id(AUTHORITY))), new MemoryAtomicKv());
        assertNull(reg.accept(lease(1, 1000, 2000, "j1"), List.of()).code);
        assertNull(reg.accept(lease(2, 1500, 3000, "j2"), List.of()).code);
        assertEquals("not_extending", reg.accept(lease(3, 1200, 4000, "j3"), List.of()).code, "renewed_at before the current one");
        assertEquals("not_extending", reg.accept(lease(3, 1600, 3000, "j3"), List.of()).code, "expires_at not later");
        assertNull(reg.accept(lease(3, 1600, 3001, "j3"), List.of()).code, "control");
    }

    @Test void freshJustificationIsTheDefaultAndExplicitChoicesAreHonoured() {
        for (Boolean fresh : new Boolean[] {null, Boolean.TRUE, Boolean.FALSE}) {
            Lease.Policy p = new Lease.Policy(List.of(id(AUTHORITY)));
            p.freshJustification = fresh;
            Lease.Registry reg = new Lease.Registry(p, new MemoryAtomicKv());
            assertNull(reg.accept(lease(1, 1000, 2000, "j1"), List.of()).code);
            String want = Boolean.FALSE.equals(fresh) ? null : "stale_justification";
            assertEquals(want, reg.accept(lease(2, 1500, 3000, "j1"), List.of()).code, String.valueOf(fresh));
        }
    }

    // ---- BreakGlass (pca-grants/src/breakglass.ts:47, 67, 171)

    @Test void aBreakGlassAuthorityIsCappedAt128() {
        Map<String, Object> b = m("v", n(1), "id", "i", "holder", "h", "grant_ref", "g", "reason_digest", "d", "max_uses", n(1), "issued_at", n(1), "expires_at", n(2), "review_within", n(1), "notify_to", "t", "authority", rep(128));
        assertTrue(BreakGlass.wellFormed(b));
        b.put("authority", rep(129));
        assertFalse(BreakGlass.wellFormed(b));
    }

    static Map<String, Object> review(Object notes, Object reviewer) { return m("v", n(1), "id", "i", "outcome", "justified", "notes_digest", notes, "at", n(1), "reviewer", reviewer); }

    @Test void reviewMembersAreCappedAt128() {
        assertTrue(BreakGlass.reviewWellFormed(review(rep(128), rep(128))));
        assertFalse(BreakGlass.reviewWellFormed(review(rep(129), "r")));
        assertFalse(BreakGlass.reviewWellFormed(review("n", rep(129))));
    }

    @Test void aReviewHolderIsCappedAt128() {
        Map<String, Object> rec = review("n", id(REVIEWER));
        rec.put("sig", sign(REVIEWER, BreakGlass.REVIEW_DOMAIN, review("n", id(REVIEWER))));
        BreakGlass.Registry reg = new BreakGlass.Registry(List.of(id(AUTHORITY)), List.of(id(REVIEWER)), new MemoryAtomicKv());
        assertEquals("unknown_break_glass", reg.review(rec, rep(128), n(5)).get("code"), "control: the record verifies and the holder is read");
        assertEquals("bad_record", reg.review(rec, rep(129), n(5)).get("code"));
    }

    // ---- GoalRunner.main: the exception counts the disagreements

    @Test void theRunnerFailsWithTheCount() throws Exception {
        String[] args = {GoalRunnerKillTest.bad().toString()};
        assertEquals("7 goal vector disagreements", assertThrows(IllegalStateException.class, () -> GoalRunner.main(args)).getMessage());
    }

    // ---- Keys.pqGenerate: its own generator, whatever BouncyCastle's process-wide default is

    @Test void pqGenerateIgnoresTheProcessWideRandom() {
        CryptoServicesRegistrar.setSecureRandom(new SecureRandom() {
            @Override public void nextBytes(byte[] b) { Arrays.fill(b, (byte) 7); }
        });
        try {
            assertFalse(Arrays.equals(Keys.pqGenerate(Pq.Prim.ML_DSA_65).pk, Keys.pqGenerate(Pq.Prim.ML_DSA_65).pk));
        } finally {
            CryptoServicesRegistrar.setSecureRandom(null);
        }
    }

    // ---- Pca.validateWireV2: a valid fresh_at does not end validation (wire.ts:188-194)

    @Test void aValidFreshAtDoesNotSkipTheChecksAfterIt() {
        @SuppressWarnings("unchecked")
        Map<String, Object> p = new LinkedHashMap<>((Map<String, Object>) FreshAtForwardTest.vec("member-equal-state").get("pcactn"));
        assertTrue(p.containsKey("fresh_at"));
        assertNull(Pca.validateWireV2(p), "control");
        p.put("prohibition_evidence", n(5));
        assertEquals("'prohibition_evidence' must be an object or array", Pca.validateWireV2(p));
    }

    // ---- LessNative.verify: a private copy of the class (K042R9LessIsolatedTest), its FFM members swapped to observe the calls

    public static int opened;
    public static final List<Long> ALLOCS = new ArrayList<>();
    public static Object noteOpen() { opened++; throw new IllegalStateException("stop before native"); }
    public static Object noteAlloc(long size) {
        ALLOCS.add(size);
        if (ALLOCS.size() == 2) throw new IllegalStateException("the message segment is what this test wants");
        return "segment";
    }
    public static void noteCopy(Object from) {}

    static void withFreshLess(LessBody body) throws Exception {
        Path lib = K042R9LessIsolatedTest.library();
        assumeTrue(lib != null && Runtime.version().feature() >= 22, "no library / no FFM here");
        K042R9LessIsolatedTest.withInputs(lib.toString(), null, null, tmp -> {
            Class<?> c = K042R9LessIsolatedTest.fresh();
            Field ff = c.getDeclaredField("FFM");
            ff.setAccessible(true);
            Object ffm = ff.get(null);
            assertTrue(ffm != null);
            body.run(c, ffm);
        });
    }
    interface LessBody { void run(Class<?> c, Object ffm) throws Exception; }

    static void swap(Object ffm, String field, String method, Class<?>... types) throws Exception {
        Field f = ffm.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(ffm, K05R3RestKillTest.class.getMethod(method, types));
    }

    static final Class<?>[] VERIFY = {byte[].class, byte[].class, byte[].class};

    /** A wrong key or signature length and a null message refuse before any native work (atlas_less.c:62-64 re-checks them: defence in depth). */
    @Test void malformedInputNeverReachesNative() throws Exception {
        withFreshLess((c, ffm) -> {
            swap(ffm, "arenaOfConfined", "noteOpen");
            byte[] pk = new byte[LessNative.PUBLIC_KEY_BYTES], sig = new byte[LessNative.SIGNATURE_MIN_BYTES], msg = {1};
            opened = 0;
            assertEquals(false, K042R9LessIsolatedTest.call(c, "verify", VERIFY, pk, msg, sig));
            assertEquals(1, opened, "control: well-formed input opens an arena");
            opened = 0;
            assertEquals(false, K042R9LessIsolatedTest.call(c, "verify", VERIFY, new byte[LessNative.PUBLIC_KEY_BYTES + 1], msg, sig), "key length");
            assertEquals(false, K042R9LessIsolatedTest.call(c, "verify", VERIFY, pk, msg, new byte[LessNative.SIGNATURE_MIN_BYTES + 1]), "signature length");
            assertEquals(false, K042R9LessIsolatedTest.call(c, "verify", VERIFY, pk, null, sig), "no message");
            assertEquals(0, opened);
        });
    }

    /** An empty message travels as a 1-byte segment with length 0, so the native call never sees a zero-sized allocation. */
    @Test void anEmptyMessageGetsAOneByteSegment() throws Exception {
        withFreshLess((c, ffm) -> {
            swap(ffm, "arenaAllocate", "noteAlloc", long.class);
            swap(ffm, "segCopyFrom", "noteCopy", Object.class);
            byte[] pk = new byte[LessNative.PUBLIC_KEY_BYTES], sig = new byte[LessNative.SIGNATURE_MIN_BYTES];
            ALLOCS.clear();
            assertEquals(false, K042R9LessIsolatedTest.call(c, "verify", VERIFY, pk, new byte[0], sig));
            assertEquals(List.of((long) LessNative.PUBLIC_KEY_BYTES, 1L), new ArrayList<>(ALLOCS));
            ALLOCS.clear();
            assertEquals(false, K042R9LessIsolatedTest.call(c, "verify", VERIFY, pk, new byte[3], sig));
            assertEquals(List.of((long) LessNative.PUBLIC_KEY_BYTES, 3L), new ArrayList<>(ALLOCS));
        });
    }
}
