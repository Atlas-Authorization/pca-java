package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Prohibitions: exact-output checks per method (evidence signing, signed-evidence verification, the monitor state validator and canonical order,
 * the window, the invariant kinds, check-and-advance attribution and its fail-closed paths).
 */
class ProhibitionsSurvivorKillTest {
    static Object j(String s) { return Json.parseLenient(s.replace('\'', '"')); }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static Json.Num n(String raw) { return new Json.Num(raw); }

    static Map<String, Object> mm(String s) { return new LinkedHashMap<>(m(j(s))); }

    static void eq(String want, Object got) { assertEquals(Json.canonicalize(j(want)), Json.canonicalize(got)); }

    static byte[] seed(int fill) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) fill);
        return s;
    }

    static final byte[] SEED = seed(9);
    static final byte[] OTHER_SEED = seed(10);
    static final Keys.EdKey KEY = Keys.edFromSeed(SEED);
    static final Keys.EdKey OTHER = Keys.edFromSeed(OTHER_SEED);

    static final String PAY = "{'action':{'verb':'pay','resource':'/r'}}";
    static final String DEL = "{'action':{'verb':'delete','resource':'/r'}}";
    static final String S0 = "{'now':1000,'seq':0,'parent':null,'ledger':{},'latched':{}}";

    static String cons(String invs) { return "{'version':1,'principal':'p','invariants':" + invs + "}"; }

    static final String NO_DEL = cons("[{'id':'no-del','kind':'never','when':{'verb':'delete'}}]");
    static final String NEVER_PAY = cons("[{'id':'np','kind':'never','when':{'verb':'pay'}}]");

    static String act(String amountJson) { return "{'action':{'verb':'pay','resource':'/r','amount':" + amountJson + "}}"; }

    static Map<String, Object> prove(String action, String con, String state) { return Prohibitions.proveSafety(j(action), j(con), j(state)); }

    static Map<String, Object> sign(Map<String, Object> ev) { return Prohibitions.signSafetyEvidence(ev, SEED, KEY.id()); }

    static Map<String, Object> signedFor(String action, String con, String state) { return sign(prove(action, con, state)); }

    static Map<String, Object> exp(String action, String con, String state) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("signer", KEY.id());
        e.put("action", j(action));
        e.put("constitution", j(con));
        e.put("state", j(state));
        return e;
    }

    static String ver(Map<String, Object> signed, Map<String, Object> expected) { return Prohibitions.verifySignedSafetyEvidence(signed, expected); }

    static String sigBy(Keys.EdKey k, String domain, String id) { return Pca.b64(k.sign(Prohibitions.domainMessage(domain, id))); }

    static Map<String, Object> signedConstitution(String invs) {
        Map<String, Object> c = mm("{'version':1,'principal':'" + KEY.id() + "','invariants':" + invs + "}");
        String id = Prohibitions.constitutionId(c);
        c.put("id", id);
        c.put("sig", sigBy(KEY, Prohibitions.CONSTITUTION_SIG_DOMAIN, id));
        return c;
    }

    /** A map that fails on the {@code nth} read of {@code key} (0 = every read), to reach a fail-closed path after validation passed. */
    static final class Flaky extends LinkedHashMap<String, Object> {
        private static final long serialVersionUID = 1L;
        final String key;
        final int nth;
        int reads;

        Flaky(Map<String, Object> from, String key, int nth) {
            super(from);
            this.key = key;
            this.nth = nth;
        }

        @Override public Object get(Object k) {
            if (key.equals(k) && (nth == 0 || ++reads >= nth)) throw new IllegalStateException("flaky read");
            return super.get(k);
        }
    }

    // ---- signSafetyEvidence -----------------------------------------------------------------------------------------------

    @Test void signSafetyEvidenceSignsBoundEvidence() {
        Map<String, Object> ev = prove(PAY, NO_DEL, S0);
        Map<String, Object> signed = sign(ev);
        assertEquals(List.of("evidence", "signer", "id", "sig"), new ArrayList<>(signed.keySet()));
        assertSame(ev, signed.get("evidence"));
        assertEquals(KEY.id(), signed.get("signer"));
        assertEquals(Prohibitions.safetyBindingId(ev, KEY.id()), signed.get("id"));
        assertTrue(IntentJs.verifyEd(KEY.id(), Prohibitions.domainMessage(Prohibitions.SAFETY_EVIDENCE_SIG_DOMAIN, (String) signed.get("id")), signed.get("sig")));
        assertNull(ver(signed, exp(PAY, NO_DEL, S0)));
    }

    static String refused(Object evidence, String signer) {
        return assertThrows(IllegalArgumentException.class, () -> Prohibitions.signSafetyEvidence(evidence, SEED, signer)).getMessage();
    }

    @Test void signSafetyEvidenceRefusesAnUnsupportedVersion() {
        String want = "signSafetyEvidence: unsupported evidence";
        for (Object notObj : new Object[] {"x", null, new ArrayList<>(), Boolean.TRUE}) assertEquals(want, refused(notObj, KEY.id()), String.valueOf(notObj));
        Map<String, Object> missing = prove(PAY, NO_DEL, S0);
        missing.remove("v");
        assertEquals(want, refused(missing, KEY.id()));
        for (Object v : new Object[] {"1", n("1.5"), n("2"), n("0"), n("-1"), Boolean.TRUE, null}) {
            Map<String, Object> ev = prove(PAY, NO_DEL, S0);
            ev.put("v", v);
            assertEquals(want, refused(ev, KEY.id()), String.valueOf(v));
        }
    }

    @Test void signSafetyEvidenceRefusesEveryUnboundDigest() {
        String want = "signSafetyEvidence: unbound evidence";
        for (String k : new String[] {"constitution", "action_digest", "state_digest"}) {
            for (Object bad : new Object[] {"", n("5"), Integer.valueOf(5), null, Prohibitions.UNHASHABLE, new ArrayList<>()}) {
                Map<String, Object> ev = prove(PAY, NO_DEL, S0);
                ev.put(k, bad);
                assertEquals(want, refused(ev, KEY.id()), k + "=" + bad);
            }
            Map<String, Object> gone = prove(PAY, NO_DEL, S0);
            gone.remove(k);
            assertEquals(want, refused(gone, KEY.id()), k + " removed");
        }
    }

    @Test void signSafetyEvidenceRefusesAMissingSigner() {
        Map<String, Object> ev = prove(PAY, NO_DEL, S0);
        assertEquals("signSafetyEvidence: signer missing", refused(ev, null));
        assertEquals("signSafetyEvidence: signer missing", refused(ev, ""));
    }

    // ---- verifySignedSafetyEvidence ---------------------------------------------------------------------------------------

    @Test void verifySignedEvidenceAcceptsTheHonestEvidenceWhateverTheSignerPinShape() {
        Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
        assertNull(ver(signed, exp(PAY, NO_DEL, S0)));
        Map<String, Object> asList = exp(PAY, NO_DEL, S0);
        asList.put("signer", new ArrayList<Object>(List.of("someone-else", KEY.id())));
        assertNull(ver(signed, asList));
    }

    @Test void verifySignedEvidenceNeedsAWellFormedPinnedSigner() {
        Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
        Object[] pins = {new ArrayList<>(), new ArrayList<Object>(List.of("")), new ArrayList<Object>(List.of(n("5"))), new ArrayList<Object>(Arrays.asList(KEY.id(), "")),
            new ArrayList<Object>(Arrays.asList(KEY.id(), null)), "", null, n("5")};
        for (Object pin : pins) {
            Map<String, Object> e = exp(PAY, NO_DEL, S0);
            e.put("signer", pin);
            assertEquals("no pinned signer", ver(signed, e), String.valueOf(pin));
        }
        Map<String, Object> gone = exp(PAY, NO_DEL, S0);
        gone.remove("signer");
        assertEquals("no pinned signer", ver(signed, gone));
    }

    @Test void verifySignedEvidenceRefusesAnUntrustedOrUnreadableSigner() {
        for (Object other : new Object[] {"someone-else", n("5"), null}) {
            Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
            signed.put("signer", other);
            assertEquals("signer not trusted", ver(signed, exp(PAY, NO_DEL, S0)), String.valueOf(other));
        }
        Map<String, Object> gone = signedFor(PAY, NO_DEL, S0);
        gone.remove("signer");
        assertEquals("signer not trusted", ver(gone, exp(PAY, NO_DEL, S0)));
        // a pin literally named like the property is not the signer either
        Map<String, Object> e = exp(PAY, NO_DEL, S0);
        e.put("signer", "signer");
        assertEquals("signer not trusted", ver(signedFor(PAY, NO_DEL, S0), e));
        e.put("signer", new ArrayList<Object>(List.of("sig", "id")));
        assertEquals("signer not trusted", ver(signedFor(PAY, NO_DEL, S0), e));
    }

    @Test void verifySignedEvidenceNeedsEveryBindingSpecified() {
        Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
        Map<String, Object> a = exp(PAY, NO_DEL, S0);
        a.remove("action");
        assertEquals("unbound: action not specified", ver(signed, a));
        Map<String, Object> c = exp(PAY, NO_DEL, S0);
        c.remove("constitution");
        assertEquals("unbound: constitution not specified", ver(signed, c));
        Map<String, Object> s = exp(PAY, NO_DEL, S0);
        s.remove("state");
        assertEquals("unbound: state not specified", ver(signed, s));
        // the digest forms satisfy the same requirement
        Map<String, Object> digests = new LinkedHashMap<>();
        digests.put("signer", KEY.id());
        digests.put("actionDigest", Pca.hashCanonical(j(PAY)));
        digests.put("constitutionId", Prohibitions.constitutionId(mm(NO_DEL)));
        digests.put("stateDigest", Prohibitions.stateDigest(j(S0)));
        assertNull(ver(signed, digests));
    }

    @Test void verifySignedEvidenceChecksTheBindingIdAndTheSignature() {
        for (Object badId : new Object[] {n("5"), "not-the-id", null}) {
            Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
            signed.put("id", badId);
            assertEquals("binding id mismatch", ver(signed, exp(PAY, NO_DEL, S0)), String.valueOf(badId));
        }
        Map<String, Object> noId = signedFor(PAY, NO_DEL, S0);
        noId.remove("id");
        assertEquals("binding id mismatch", ver(noId, exp(PAY, NO_DEL, S0)));
        // evidence edited after signing no longer matches its binding id
        Map<String, Object> edited = signedFor(PAY, NO_DEL, S0);
        m(edited.get("evidence")).put("now", n("1"));
        assertEquals("binding id mismatch", ver(edited, exp(PAY, NO_DEL, S0)));

        for (Object badSig : new Object[] {n("5"), null}) {
            Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
            signed.put("sig", badSig);
            assertEquals("bad signature", ver(signed, exp(PAY, NO_DEL, S0)), String.valueOf(badSig));
        }
        Map<String, Object> noSig = signedFor(PAY, NO_DEL, S0);
        noSig.remove("sig");
        assertEquals("bad signature", ver(noSig, exp(PAY, NO_DEL, S0)));
        Map<String, Object> foreign = signedFor(PAY, NO_DEL, S0);
        foreign.put("sig", sigBy(OTHER, Prohibitions.SAFETY_EVIDENCE_SIG_DOMAIN, (String) foreign.get("id")));
        assertEquals("bad signature", ver(foreign, exp(PAY, NO_DEL, S0)));
    }

    @Test void verifySignedEvidenceRefusesMalformedInputAndAnUnsupportedVersion() {
        Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
        Map<String, Object> e = exp(PAY, NO_DEL, S0);
        assertEquals("malformed input", Prohibitions.verifySignedSafetyEvidence(null, e));
        assertEquals("malformed input", Prohibitions.verifySignedSafetyEvidence("x", e));
        assertEquals("malformed input", Prohibitions.verifySignedSafetyEvidence(signed, null));
        assertEquals("malformed input", Prohibitions.verifySignedSafetyEvidence(signed, "x"));
        Map<String, Object> noEv = new LinkedHashMap<>(signed);
        noEv.remove("evidence");
        assertEquals("malformed input", Prohibitions.verifySignedSafetyEvidence(noEv, e));
        noEv.put("evidence", "x");
        assertEquals("malformed input", Prohibitions.verifySignedSafetyEvidence(noEv, e));
        for (Object v : new Object[] {n("2"), "1", n("1.5"), Boolean.TRUE, null}) {
            Map<String, Object> s = signedFor(PAY, NO_DEL, S0);
            m(s.get("evidence")).put("v", v);
            assertEquals("unsupported evidence version", ver(s, e), String.valueOf(v));
        }
    }

    @Test void verifySignedEvidenceChecksTheActionBinding() {
        Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
        Map<String, Object> both = exp(PAY, NO_DEL, S0);
        both.put("actionDigest", "zzz");
        assertEquals("expected action and digest disagree", ver(signed, both));
        both.put("actionDigest", Pca.hashCanonical(j(PAY)));
        assertNull(ver(signed, both));
        assertEquals("action digest mismatch (evidence bound to another action)", ver(signed, exp(DEL, NO_DEL, S0)));
        Map<String, Object> onlyDigest = exp(PAY, NO_DEL, S0);
        onlyDigest.remove("action");
        onlyDigest.put("actionDigest", "zzz");
        assertEquals("action digest mismatch (evidence bound to another action)", ver(signed, onlyDigest));
    }

    @Test void verifySignedEvidenceChecksTheConstitutionBinding() {
        Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
        String id = Prohibitions.constitutionId(mm(NO_DEL));
        Map<String, Object> both = exp(PAY, NO_DEL, S0);
        both.put("constitutionId", "zzz");
        assertEquals("expected constitution and id disagree", ver(signed, both));
        both.put("constitutionId", id);
        assertNull(ver(signed, both));
        assertEquals("constitution mismatch (evidence bound to another constitution)", ver(signed, exp(PAY, NEVER_PAY, S0)));
        Map<String, Object> onlyId = exp(PAY, NO_DEL, S0);
        onlyId.remove("constitution");
        onlyId.put("constitutionId", "zzz");
        assertEquals("constitution mismatch (evidence bound to another constitution)", ver(signed, onlyId));
    }

    @Test void verifySignedEvidenceChecksTheStateBinding() {
        Map<String, Object> signed = signedFor(PAY, NO_DEL, S0);
        Map<String, Object> both = exp(PAY, NO_DEL, S0);
        both.put("stateDigest", "zzz");
        assertEquals("expected state and digest disagree", ver(signed, both));
        both.put("stateDigest", Prohibitions.stateDigest(j(S0)));
        assertNull(ver(signed, both));
        String later = "{'now':2000,'seq':0,'parent':null,'ledger':{},'latched':{}}";
        assertEquals("state digest mismatch (evidence bound to another state)", ver(signed, exp(PAY, NO_DEL, later)));
        Map<String, Object> onlyDigest = exp(PAY, NO_DEL, S0);
        onlyDigest.remove("state");
        onlyDigest.put("stateDigest", "zzz");
        assertEquals("state digest mismatch (evidence bound to another state)", ver(signed, onlyDigest));
    }

    @Test void verifySignedEvidencePinsThePrincipalOfASignedConstitution() {
        String invs = "[{'id':'no-del','kind':'never','when':{'verb':'delete'}}]";
        Map<String, Object> sc = signedConstitution(invs);
        Map<String, Object> ev = Prohibitions.proveSafety(j(PAY), sc, j(S0));
        Map<String, Object> signed = sign(ev);
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("signer", KEY.id());
        e.put("action", j(PAY));
        e.put("constitution", sc);
        e.put("state", j(S0));
        e.put("principal", KEY.id());
        assertNull(ver(signed, e));
        for (Object p : new Object[] {"someone-else", n("5"), null}) {
            e.put("principal", p);
            assertEquals("constitution not authentic: principal mismatch", ver(signed, e), String.valueOf(p));
        }
        e.put("principal", KEY.id());

        Map<String, Object> forged = new LinkedHashMap<>(sc);
        forged.put("sig", sigBy(OTHER, Prohibitions.CONSTITUTION_SIG_DOMAIN, (String) sc.get("id")));
        e.put("constitution", forged);
        assertEquals("constitution not authentic: bad signature", ver(signed, e));
        Map<String, Object> reid = new LinkedHashMap<>(sc);
        reid.put("id", "x");
        e.put("constitution", reid);
        assertEquals("constitution not authentic: id does not match content", ver(signed, e));

        Map<String, Object> unsigned = new LinkedHashMap<>(sc);
        unsigned.remove("sig");
        e.put("constitution", unsigned);
        assertEquals("principal pin requires a signed constitution", ver(signed, e));
        e.put("constitution", "x");
        assertEquals("principal pin requires a signed constitution", ver(signed, e));
        e.remove("constitution");
        e.put("constitutionId", sc.get("id"));
        assertEquals("principal pin requires a signed constitution", ver(signed, e));
    }

    @Test void verifySignedEvidenceRefusesAMalformedExpectedConstitution() {
        String bad = cons("[{'kind':'never','when':{'verb':'x'}}]");
        Map<String, Object> signed = signedFor(PAY, bad, S0);
        assertEquals("constitution malformed: <no id>: missing id", ver(signed, exp(PAY, bad, S0)));
    }

    @Test void verifySignedEvidenceChecksTheVerdictAgainstTheRows() {
        Map<String, Object> e = exp(PAY, NO_DEL, S0);
        String inconsistent = "evidence verdict inconsistent with rows";

        Map<String, Object> notList = prove(PAY, NO_DEL, S0);
        notList.put("evaluated", "x");
        assertEquals("malformed evidence", ver(sign(notList), e));
        Map<String, Object> noViolated = prove(PAY, NO_DEL, S0);
        noViolated.put("violated", null);
        assertEquals("malformed evidence", ver(sign(noViolated), e));
        Map<String, Object> badRowId = prove(PAY, NO_DEL, S0);
        badRowId.put("evaluated", new ArrayList<Object>(List.of(mm("{'id':5,'result':'pass'}"))));
        assertEquals("malformed evidence", ver(sign(badRowId), e));

        Map<String, Object> forgedOk = prove(DEL, NO_DEL, S0);
        forgedOk.put("ok", Boolean.TRUE);
        assertEquals(inconsistent, ver(sign(forgedOk), exp(DEL, NO_DEL, S0)));
        Map<String, Object> forgedNotOk = prove(PAY, NO_DEL, S0);
        forgedNotOk.put("ok", Boolean.FALSE);
        assertEquals(inconsistent, ver(sign(forgedNotOk), e));
        Map<String, Object> noOk = prove(PAY, NO_DEL, S0);
        noOk.remove("ok");
        assertEquals(inconsistent, ver(sign(noOk), e));
        Map<String, Object> textOk = prove(PAY, NO_DEL, S0);
        textOk.put("ok", "true");
        assertEquals(inconsistent, ver(sign(textOk), e));
        Map<String, Object> extraViolated = prove(PAY, NO_DEL, S0);
        extraViolated.put("violated", new ArrayList<Object>(List.of("x")));
        assertEquals(inconsistent, ver(sign(extraViolated), e));
        Map<String, Object> nullRow = prove(PAY, NO_DEL, S0);
        nullRow.put("evaluated", new ArrayList<Object>(Arrays.asList((Object) null)));
        assertEquals(inconsistent, ver(sign(nullRow), e));
    }

    @Test void verifySignedEvidenceRecomputesWhenEverythingIsGiven() {
        Map<String, Object> e = exp(DEL, NO_DEL, S0);
        // honest violation evidence: refused as a violation, accepted when the verdict is not required
        Map<String, Object> honest = signedFor(DEL, NO_DEL, S0);
        assertEquals("prohibition violated: no-del", ver(honest, e));
        e.put("requireOk", Boolean.TRUE);
        assertEquals("prohibition violated: no-del", ver(honest, e));
        e.put("requireOk", "false");
        assertEquals("prohibition violated: no-del", ver(honest, e));
        e.put("requireOk", Boolean.FALSE);
        assertNull(ver(honest, e));

        // an ok verdict that does not reproduce is refused with the recomputation's reason
        Map<String, Object> forged = prove(DEL, NO_DEL, S0);
        Map<String, Object> row = m(l(forged.get("evaluated")).get(0));
        row.put("result", "pass");
        row.remove("reason");
        forged.put("violated", new ArrayList<>());
        forged.put("ok", Boolean.TRUE);
        assertEquals("evidence does not reproduce", ver(sign(forged), exp(DEL, NO_DEL, S0)));

        // a violation verdict whose rows were edited is refused with the recomputation's reason, not as a plain violation
        Map<String, Object> edited = prove(DEL, NO_DEL, S0);
        m(l(edited.get("evaluated")).get(0)).put("reason", "tampered");
        Map<String, Object> e2 = exp(DEL, NO_DEL, S0);
        e2.put("requireOk", Boolean.FALSE);
        assertEquals("evidence does not reproduce", ver(sign(edited), e2));

        assertNull(ver(signedFor(PAY, NO_DEL, S0), exp(PAY, NO_DEL, S0)));
    }

    @Test void verifySignedEvidenceWithoutAFullRecomputationNeedsTheRowsToCoverTheConstitution() {
        String two = cons("[{'id':'a','kind':'never','when':{'verb':'delete'}},{'id':'b','kind':'never','when':{'verb':'wipe'}}]");
        Map<String, Object> digests = new LinkedHashMap<>();
        digests.put("signer", KEY.id());
        digests.put("actionDigest", Pca.hashCanonical(j(PAY)));
        digests.put("constitution", j(two));
        digests.put("stateDigest", Prohibitions.stateDigest(j(S0)));
        assertNull(ver(signedFor(PAY, two, S0), digests));

        String missing = "evidence does not cover every invariant";
        Map<String, Object> fewer = prove(PAY, two, S0);
        l(fewer.get("evaluated")).remove(1);
        assertEquals(missing, ver(sign(fewer), digests));
        Map<String, Object> none = prove(PAY, two, S0);
        none.put("evaluated", new ArrayList<>());
        assertEquals(missing, ver(sign(none), digests));
        Map<String, Object> swapped = prove(PAY, two, S0);
        java.util.Collections.swap(l(swapped.get("evaluated")), 0, 1);
        assertEquals(missing, ver(sign(swapped), digests));
        Map<String, Object> renamed = prove(PAY, two, S0);
        m(l(renamed.get("evaluated")).get(1)).put("id", "c");
        assertEquals(missing, ver(sign(renamed), digests));
        Map<String, Object> more = prove(PAY, two, S0);
        l(more.get("evaluated")).add(mm("{'id':'c','kind':'never','result':'pass'}"));
        assertEquals(missing, ver(sign(more), digests));

        // a violation verdict is judged by requireOk alone here
        Map<String, Object> violated = new LinkedHashMap<>(digests);
        violated.put("actionDigest", Pca.hashCanonical(j(DEL)));
        Map<String, Object> signedViolation = signedFor(DEL, two, S0);
        assertEquals("prohibition violated: a", ver(signedViolation, violated));
        violated.put("requireOk", Boolean.FALSE);
        assertNull(ver(signedViolation, violated));
    }

    // ---- verifyConstitution -----------------------------------------------------------------------------------------------

    @Test void verifyConstitutionAcceptsASignedOneAndNamesWhatIsWrongOtherwise() {
        String invs = "[{'id':'no-del','kind':'never','when':{'verb':'delete'}}]";
        Map<String, Object> sc = signedConstitution(invs);
        assertNull(Prohibitions.verifyConstitution(sc, null));
        assertNull(Prohibitions.verifyConstitution(sc, KEY.id()));
        assertEquals("principal mismatch", Prohibitions.verifyConstitution(sc, "someone-else"));
        Map<String, Object> foreign = new LinkedHashMap<>(sc);
        foreign.put("sig", sigBy(OTHER, Prohibitions.CONSTITUTION_SIG_DOMAIN, (String) sc.get("id")));
        assertEquals("bad signature", Prohibitions.verifyConstitution(foreign, null));
        Map<String, Object> noSig = new LinkedHashMap<>(sc);
        noSig.remove("sig");
        assertEquals("bad signature", Prohibitions.verifyConstitution(noSig, null));
        noSig.put("sig", n("5"));
        assertEquals("bad signature", Prohibitions.verifyConstitution(noSig, null));
        Map<String, Object> reid = new LinkedHashMap<>(sc);
        reid.put("id", "x");
        assertEquals("id does not match content", Prohibitions.verifyConstitution(reid, null));
    }

    // ---- stateProblem / canonicalState ------------------------------------------------------------------------------------

    @Test void aMalformedStateShapeIsReportedBeforeAnySeqProblem() {
        String shape = "malformed monitor state";
        assertEquals("malformed monitor state: seq", Prohibitions.stateProblem(withSeq(S0)));
        for (Object bad : new Object[] {"x", null, new ArrayList<>(), n("1e999")}) {
            Map<String, Object> a = withSeq(S0);
            a.put("now", bad);
            assertEquals(shape, Prohibitions.stateProblem(a), "now=" + bad);
        }
        for (Object bad : new Object[] {"x", null, new ArrayList<>(), n("5")}) {
            Map<String, Object> a = withSeq(S0);
            a.put("ledger", bad);
            assertEquals(shape, Prohibitions.stateProblem(a), "ledger=" + bad);
            Map<String, Object> b = withSeq(S0);
            b.put("latched", bad);
            assertEquals(shape, Prohibitions.stateProblem(b), "latched=" + bad);
        }
        Map<String, Object> gone = withSeq(S0);
        gone.remove("latched");
        assertEquals(shape, Prohibitions.stateProblem(gone));
    }

    static Map<String, Object> withSeq(String state) {
        Map<String, Object> s = mm(state);
        s.put("seq", n("-1"));
        return s;
    }

    @Test void aStateWhoseReadsFailIsMalformedAndNotAnObject() {
        assertEquals("malformed monitor state", Prohibitions.stateProblem(new Flaky(mm(S0), "seq", 0)));
        assertEquals("malformed monitor state", Prohibitions.stateProblem("x"));
        assertEquals("malformed monitor state", Prohibitions.stateProblem(null));
        assertEquals("malformed monitor state", Prohibitions.stateProblem(new ArrayList<>()));
        assertNull(Prohibitions.stateProblem(mm(S0)));
    }

    @Test void canonicalStateThrowsTheProblem() {
        assertEquals("malformed monitor state", assertThrows(IllegalArgumentException.class, () -> Prohibitions.canonicalState("x")).getMessage());
        assertEquals("malformed monitor state: seq", assertThrows(IllegalArgumentException.class, () -> Prohibitions.canonicalState(withSeq(S0))).getMessage());
        assertEquals("malformed monitor state: seq", assertThrows(IllegalArgumentException.class, () -> Prohibitions.stateDigest(withSeq(S0))).getMessage());
    }

    static List<String> pairs(Object canon, String key) {
        List<String> out = new ArrayList<>();
        for (Object e : l(m(m(canon).get("ledger")).get(key))) out.add(m(e).get("t") + ":" + m(e).get("amount"));
        return out;
    }

    @Test void canonicalStateOrdersTheLedgerByTimeThenAmount() {
        Map<String, Object> s = mm("{'now':100,'seq':0,'parent':null,'latched':{},'ledger':{'k':[{'t':3,'amount':1},{'t':1,'amount':9},{'t':2,'amount':5}],"
            + "'q':[{'t':5,'amount':3},{'t':5,'amount':1},{'t':4,'amount':9},{'t':5,'amount':2}],'r':[{'t':7,'amount':1},{'t':7,'amount':2},{'t':6,'amount':8}],"
            + "'u':[{'t':8,'amount':3},{'t':8,'amount':2},{'t':8,'amount':1}]}}");
        Map<String, Object> canon = Prohibitions.canonicalState(s);
        assertEquals(List.of("1:9", "2:5", "3:1"), pairs(canon, "k"));
        assertEquals(List.of("4:9", "5:1", "5:2", "5:3"), pairs(canon, "q"));
        assertEquals(List.of("6:8", "7:1", "7:2"), pairs(canon, "r"));
        assertEquals(List.of("8:1", "8:2", "8:3"), pairs(canon, "u"));
    }

    @Test void canonicalStateKeepsEntriesWithEqualTimeAndAmountInTheirOrder() {
        Json.Num[] marks = new Json.Num[3];
        List<Object> entries = new ArrayList<>();
        for (int i = 0; i < marks.length; i++) {
            marks[i] = n("7");
            entries.add(new LinkedHashMap<String, Object>(Map.of("t", n("5"), "amount", marks[i])));
        }
        Map<String, Object> s = mm("{'now':100,'seq':0,'parent':null,'latched':{}}");
        Map<String, Object> ledger = new LinkedHashMap<>();
        ledger.put("k", entries);
        s.put("ledger", ledger);
        List<Object> out = l(m(Prohibitions.canonicalState(s).get("ledger")).get("k"));
        for (int i = 0; i < marks.length; i++) assertSame(marks[i], m(out.get(i)).get("amount"), "entry " + i);
    }

    @Test void canonicalStateSortsALargeTiedLedgerStably() {
        int count = 200;
        Json.Num[] marks = new Json.Num[count];
        List<Object> entries = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            marks[i] = n("3");
            entries.add(new LinkedHashMap<String, Object>(Map.of("t", n(String.valueOf((count - i) % 4)), "amount", marks[i])));
        }
        Map<String, Object> s = mm("{'now':100,'seq':0,'parent':null,'latched':{}}");
        Map<String, Object> ledger = new LinkedHashMap<>();
        ledger.put("k", entries);
        s.put("ledger", ledger);
        List<Object> out = l(m(Prohibitions.canonicalState(s).get("ledger")).get("k"));
        assertEquals(count, out.size());
        int at = 0;
        for (int t = 0; t < 4; t++) {
            for (int i = 0; i < count; i++) {
                if ((count - i) % 4 != t) continue;
                assertSame(marks[i], m(out.get(at)).get("amount"), "t=" + t + " i=" + i);
                at++;
            }
        }
        assertEquals(count, at);
    }

    @Test void emptyStateIsTheGenesisState() {
        Map<String, Object> s = Prohibitions.emptyState(n("42"));
        assertEquals(List.of("now", "seq", "parent", "ledger", "latched"), new ArrayList<>(s.keySet()));
        assertEquals("42", s.get("now").toString());
        assertEquals("0", s.get("seq").toString());
        assertTrue(s.containsKey("parent"));
        assertNull(s.get("parent"));
        assertEquals(new LinkedHashMap<String, Object>(), s.get("ledger"));
        assertEquals(new LinkedHashMap<String, Object>(), s.get("latched"));
        assertNull(Prohibitions.stateProblem(s));
    }

    // ---- validateInvariant ------------------------------------------------------------------------------------------------

    @Test void aWellFormedInvariantYieldsAnEmptyListTheCallerMayExtend() {
        String[] valid = {
            "{'id':'a','kind':'never','when':{'verb':'x'}}",
            "{'id':'a','kind':'never_unless','when':{'verb':'x'},'unless':[{'field':'action.verb','op':'eq','value':'x'}]}",
            "{'id':'a','kind':'cap','when':{'verb':'x'},'amount':'action.amount','max':5}",
            "{'id':'a','kind':'rate','when':{'verb':'x'},'max':5,'window_secs':60}",
            "{'id':'a','kind':'never_after','after':{'verb':'x'},'forbid':{'verb':'y'}}",
            "{'id':'a','kind':'require_prior','when':{'verb':'x'},'prior':{'verb':'y'}}",
            "{'id':'a','kind':'require_approval_over','when':{'verb':'x'},'amount':'action.amount','threshold':5,'approved':[{'field':'action.verb','op':'eq','value':'x'}]}"};
        for (String v : valid) {
            List<String> r = Prohibitions.validateInvariant(j(v));
            assertTrue(r.isEmpty(), v);
            r.add("extra");
            assertEquals(List.of("extra"), r, v);
        }
    }

    // ---- invariant kinds ---------------------------------------------------------------------------------------------------

    @Test void aCapReadsTheAmountAndAddsToTheWindow() {
        String cap = cons("[{'id':'c','kind':'cap','when':{'verb':'pay'},'amount':'action.amount','max':10}]");
        Map<String, Object> ok10 = Prohibitions.checkProhibitions(j(act("10")), j(cap), j(S0));
        assertEquals(true, ok10.get("ok"));
        assertEquals(true, Prohibitions.checkProhibitions(j(act("0")), j(cap), j(S0)).get("ok"));
        for (String bad : new String[] {"-1", "'5'", "true", "null"}) {
            Map<String, Object> r = Prohibitions.checkProhibitions(j(act(bad)), j(cap), j(S0));
            assertEquals(false, r.get("ok"), bad);
            assertEquals(List.of("c: amount unresolvable (fail closed)"), r.get("reasons"), bad);
        }
        Map<String, Object> missing = Prohibitions.checkProhibitions(j(PAY), j(cap), j(S0));
        assertEquals(List.of("c: amount unresolvable (fail closed)"), missing.get("reasons"));
        assertEquals(List.of("c: cap exceeded: 0 + 11 > 10"), Prohibitions.checkProhibitions(j(act("11")), j(cap), j(S0)).get("reasons"));
        assertEquals(List.of("c: cap exceeded: 0 + 10.5 > 10"), Prohibitions.checkProhibitions(j(act("10.5")), j(cap), j(S0)).get("reasons"));
    }

    @Test void anApprovalIsRequiredOnlyOverTheThresholdOrForAnUnreadableAmount() {
        String app = cons("[{'id':'a','kind':'require_approval_over','when':{'verb':'pay'},'amount':'action.amount','threshold':100,"
            + "'approved':[{'field':'action.approved','op':'eq','value':true}]}]");
        String need = "a: approval required over 100";
        for (String amount : new String[] {"0", "100"}) {
            assertEquals(true, Prohibitions.checkProhibitions(j(act(amount)), j(app), j(S0)).get("ok"), amount);
        }
        assertEquals(List.of(need), Prohibitions.checkProhibitions(j(act("101")), j(app), j(S0)).get("reasons"));
        assertEquals(List.of(need), Prohibitions.checkProhibitions(j(act("100.5")), j(app), j(S0)).get("reasons"));
        for (String bad : new String[] {"-1", "'5'", "null"}) {
            assertEquals(List.of(need), Prohibitions.checkProhibitions(j(act(bad)), j(app), j(S0)).get("reasons"), bad);
        }
        assertEquals(List.of(need), Prohibitions.checkProhibitions(j(PAY), j(app), j(S0)).get("reasons"));
        String yes = "{'action':{'verb':'pay','resource':'/r','approved':true,'amount':%s}}";
        for (String amount : new String[] {"101", "-1", "'5'"}) {
            assertEquals(true, Prohibitions.checkProhibitions(j(String.format(yes, amount)), j(app), j(S0)).get("ok"), amount);
        }
        assertEquals(true, Prohibitions.checkProhibitions(j("{'action':{'verb':'pay','resource':'/r','approved':true}}"), j(app), j(S0)).get("ok"));
        assertEquals(List.of(need), Prohibitions.checkProhibitions(j("{'action':{'verb':'pay','resource':'/r','approved':false,'amount':101}}"), j(app), j(S0)).get("reasons"));
    }

    @Test void theWindowCountsEntriesAfterItsStartUpToNowInTimeOrder() {
        String state = "{'now':10000,'seq':0,'parent':null,'latched':{},'ledger':{'c':[{'t':10000,'amount':1000},{'t':5001,'amount':1},{'t':5000,'amount':10},{'t':4000,'amount':100}],"
            + "'r':[{'t':10000,'amount':1},{'t':5001,'amount':1},{'t':5000,'amount':1},{'t':4000,'amount':1}]}}";
        String cap = cons("[{'id':'c','kind':'cap','when':{'verb':'pay'},'amount':'action.amount','max':0,'window_secs':5}]");
        assertEquals(List.of("c: cap exceeded: 1001 + 1 > 0"), Prohibitions.checkProhibitions(j(act("1")), j(cap), j(state)).get("reasons"));
        String rate = cons("[{'id':'r','kind':'rate','when':{'verb':'pay'},'max':1,'window_secs':5}]");
        assertEquals(List.of("r: rate exceeded: 3 > 1 per 5s"), Prohibitions.checkProhibitions(j(PAY), j(rate), j(state)).get("reasons"));
    }

    @Test void aCapSumsTheWindowInTimeOrder() {
        String state = "{'now':1000,'seq':0,'parent':null,'latched':{},'ledger':{'c':[{'t':3,'amount':10000000000000000},{'t':1,'amount':1},{'t':2,'amount':1}]}}";
        String cap = cons("[{'id':'c','kind':'cap','when':{'verb':'pay'},'amount':'action.amount','max':5}]");
        assertEquals(List.of("c: cap exceeded: 10000000000000002 + 1 > 5"), Prohibitions.checkProhibitions(j(act("1")), j(cap), j(state)).get("reasons"));
    }

    // ---- checkProhibitions fail-closed paths ------------------------------------------------------------------------------

    @Test void aInvariantWhoseEvaluationThrowsIsAViolatedRow() {
        Map<String, Object> c = mm(NO_DEL);
        Map<String, Object> inv = new Flaky(mm("{'id':'n','kind':'never','when':{'verb':'pay'}}"), "when", 2);
        c.put("invariants", new ArrayList<Object>(List.of(inv)));
        Map<String, Object> r = Prohibitions.checkProhibitions(j(PAY), c, j(S0));
        eq("{'ok':false,'violated':['n'],'reasons':['n: evaluation error (fail closed)'],'evaluated':[{'id':'n','kind':'never','result':'violated','reason':'evaluation error (fail closed)'}]}", r);
    }

    @Test void aMonitorFailureOutsideTheRowsIsOneStructuralViolation() {
        Map<String, Object> c = new Flaky(mm(NO_DEL), "invariants", 2);
        Map<String, Object> r = Prohibitions.checkProhibitions(j(PAY), c, j(S0));
        eq("{'ok':false,'violated':['<monitor>'],'reasons':['monitor error (fail closed)'],'evaluated':[{'id':'<monitor>','kind':'structural','result':'violated','reason':'monitor error (fail closed)'}]}", r);
    }

    // ---- advance ----------------------------------------------------------------------------------------------------------

    @Test void onlyARequirePriorInvariantLatchesOnItsPriorAction() {
        String c = cons("[{'id':'x','kind':'never','when':{'verb':'delete'},'prior':{'verb':'pay'}},"
            + "{'id':'y','kind':'never_unless','when':{'verb':'delete'},'unless':[{'field':'action.verb','op':'eq','value':'x'}],'prior':{'verb':'pay'}},"
            + "{'id':'z','kind':'require_approval_over','when':{'verb':'delete'},'amount':'action.amount','threshold':1,'approved':[{'field':'action.verb','op':'eq','value':'x'}],'prior':{'verb':'pay'}}]");
        Map<String, Object> r = Prohibitions.advanceStateStrict(j(PAY), j(c), j(S0), null);
        assertEquals(true, r.get("ok"), String.valueOf(r));
        assertEquals(new LinkedHashMap<String, Object>(), m(r.get("state")).get("latched"));

        String rp = cons("[{'id':'rp','kind':'require_prior','when':{'verb':'delete'},'prior':{'verb':'pay'}}]");
        Map<String, Object> latched = Prohibitions.advanceStateStrict(j(PAY), j(rp), j(S0), n("1500"));
        eq("{'rp':1500}", m(latched.get("state")).get("latched"));
        Map<String, Object> other = Prohibitions.advanceStateStrict(j(DEL), j(rp), j(S0), n("1500"));
        eq("{}", m(other.get("state")).get("latched"));
        // an already latched prerequisite keeps its first time
        Map<String, Object> again = Prohibitions.advanceStateStrict(j(PAY), j(rp), latched.get("state"), n("1700"));
        eq("{'rp':1500}", m(again.get("state")).get("latched"));
    }

    @Test void aCapAdvanceRefusesAnUnreadableAmountByName() {
        String cap = cons("[{'id':'c','kind':'cap','when':{'verb':'pay'},'amount':'action.amount','max':10}]");
        for (String bad : new String[] {"-1", "'5'", "true"}) {
            Map<String, Object> r = Prohibitions.advanceStateStrict(j(act(bad)), j(cap), j(S0), null);
            assertEquals(false, r.get("ok"), bad);
            assertEquals("c: amount unresolvable", r.get("reason"), bad);
        }
        Map<String, Object> missing = Prohibitions.advanceStateStrict(j(PAY), j(cap), j(S0), null);
        assertEquals("c: amount unresolvable", missing.get("reason"));
        Map<String, Object> zero = Prohibitions.advanceStateStrict(j(act("0")), j(cap), j(S0), null);
        assertEquals(true, zero.get("ok"));
        eq("{'c':[{'t':1000,'amount':0}]}", m(zero.get("state")).get("ledger"));
    }

    @Test void whenAffirmativeRequiresAWellFormedTriggerThatMatches() {
        Map<String, Object> ctx = m(j(PAY));
        assertTrue(Prohibitions.whenAffirmative(j("{'verb':'pay'}"), ctx));
        assertFalse(Prohibitions.whenAffirmative(j("{'verb':'delete'}"), ctx));
        // the verb list matches 'pay' but is not well formed, so it never counts as affirmative
        assertFalse(Prohibitions.whenAffirmative(j("{'verb':['pay',5]}"), ctx));
        assertFalse(Prohibitions.whenAffirmative(j("{'verb':['pay','']}"), ctx));
        assertFalse(Prohibitions.whenAffirmative(j("{'verb':'pay','resource':5}"), ctx));
        assertFalse(Prohibitions.whenAffirmative(null, ctx));
        assertFalse(Prohibitions.whenAffirmative("x", ctx));
        // a trigger that cannot even be read is not affirmative
        assertFalse(Prohibitions.whenAffirmative(new Flaky(mm("{'verb':'pay'}"), "verb", 0), ctx));
    }

    // ---- check-and-advance --------------------------------------------------------------------------------------------------

    @Test void checkAndAdvanceNamesWhoRefused() {
        List<String> keys = List.of("allow", "decidedBy", "evidence", "prohibition", "next");
        Map<String, Object> state = mm(S0);

        Map<String, Object> prohibited = Prohibitions.checkAndAdvance(true, j(PAY), j(NEVER_PAY), state, null, null);
        assertEquals(false, prohibited.get("allow"));
        assertEquals("prohibition", prohibited.get("decidedBy"));
        assertEquals(keys, new ArrayList<>(prohibited.keySet()));
        assertSame(state, prohibited.get("next"));

        Map<String, Object> both = Prohibitions.checkAndAdvance(false, j(PAY), j(NEVER_PAY), state, null, null);
        assertEquals("prohibition", both.get("decidedBy"));
        assertEquals(keys, new ArrayList<>(both.keySet()));

        Map<String, Object> notPermitted = Prohibitions.checkAndAdvance(false, j(PAY), j(NO_DEL), state, null, null);
        assertEquals(false, notPermitted.get("allow"));
        assertEquals("permission", notPermitted.get("decidedBy"));
        assertEquals(keys, new ArrayList<>(notPermitted.keySet()));
        assertSame(state, notPermitted.get("next"));

        Map<String, Object> allowed = Prohibitions.checkAndAdvance(true, j(PAY), j(NO_DEL), state, null, null);
        assertEquals(true, allowed.get("allow"));
        assertEquals("none", allowed.get("decidedBy"));
        assertEquals(keys, new ArrayList<>(allowed.keySet()));
        assertEquals("1", m(allowed.get("next")).get("seq").toString());

        // a stale head names the state, even when a prohibition also applies
        Map<String, Object> stale = Prohibitions.checkAndAdvance(true, j(PAY), j(NEVER_PAY), state, n("5"), null);
        assertEquals("state", stale.get("decidedBy"));
        assertEquals("stale state head (seq)", stale.get("reason"));
        assertEquals(List.of("allow", "decidedBy", "evidence", "prohibition", "next", "reason"), new ArrayList<>(stale.keySet()));
    }

    @Test void aStateWhoseReadsFailRefusesAsStateInsteadOfThrowing() {
        Map<String, Object> state = new Flaky(mm(S0), "seq", 0);
        Map<String, Object> r = Prohibitions.checkAndAdvance(true, j(PAY), j(NO_DEL), state, n("0"), null);
        assertEquals(false, r.get("allow"));
        assertEquals("state", r.get("decidedBy"));
        assertEquals("check-and-advance error (fail closed)", r.get("reason"));
        assertSame(state, r.get("next"));
        assertEquals(List.of("allow", "decidedBy", "evidence", "prohibition", "next", "reason"), new ArrayList<>(r.keySet()));
        assertEquals(false, m(r.get("prohibition")).get("ok"));
        assertEquals(false, m(r.get("evidence")).get("ok"));
    }

    @Test void theExpectedSeqComparesNumbersLikeJavaScript() {
        Map<String, Object> state = mm(S0);
        // -0 === 0
        assertEquals(true, Prohibitions.checkAndAdvance(true, j(PAY), j(NO_DEL), state, n("-0"), null).get("allow"));
        assertEquals(true, Prohibitions.checkAndAdvance(true, j(PAY), j(NO_DEL), state, n("0.0"), null).get("allow"));
        assertEquals(true, Prohibitions.checkAndAdvance(true, j(PAY), j(NO_DEL), state, Long.valueOf(0), null).get("allow"));
        for (Object bad : new Object[] {n("1"), "0", Boolean.FALSE, new ArrayList<>()}) {
            assertEquals("stale state head (seq)", Prohibitions.checkAndAdvance(true, j(PAY), j(NO_DEL), state, bad, null).get("reason"), String.valueOf(bad));
        }
        // a state head that is not a number is never the expected one, and nothing throws
        Map<String, Object> odd = mm(S0);
        odd.put("seq", "a");
        Map<String, Object> r = Prohibitions.checkAndAdvance(true, j(PAY), j(NO_DEL), odd, n("0"), null);
        assertEquals("stale state head (seq)", r.get("reason"));
    }
}
