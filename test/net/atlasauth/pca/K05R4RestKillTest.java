package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.bits;
import static net.atlasauth.pca.AttestTestDer.integer;
import static net.atlasauth.pca.AttestTestDer.name;
import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static net.atlasauth.pca.IntentV2KillTest.list;
import static net.atlasauth.pca.IntentV2KillTest.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills: IntentV2 reviewers / unpinned traits, IntentRevocation epoch suites, NullSafe.set, Sigstore.namedBy. */
public class K05R4RestKillTest {
    static final String REVIEWERS_ERR = "reviewers must be {keys: [...]}";

    /** intent-v2.ts:83: a present reviewers member must carry a keys array. */
    @Test void reviewersMustCarryAKeysArray() {
        assertEquals(REVIEWERS_ERR, IntentV2.contextError(IntentV2.Context.fromJson(map("reviewers", map()))));
        assertEquals(REVIEWERS_ERR, IntentV2.contextError(IntentV2.Context.fromJson(map("reviewers", map("keys", map())))));
        assertEquals(REVIEWERS_ERR, IntentV2.contextError(IntentV2.Context.fromJson(map("reviewers", 5L))));
        assertNull(IntentV2.contextError(IntentV2.Context.fromJson(map("reviewers", map("keys", list())))));
        assertNull(IntentV2.contextError(IntentV2.Context.fromJson(map())));
    }

    /** intent-v2.ts:623: a v2 schema the closed-world check accepted reports traits even with no pin on the grant. */
    @Test void anUnpinnedV2SchemaStillReportsTraits() throws Exception {
        Map<String, Object> d = K05Rule22WiringTest.doc("rule22-allow", null);
        List<String> got = K05Rule22WiringTest.run(K05Rule22WiringTest.grant(null), K05Rule22WiringTest.context(d));
        assertEquals(2, got.size(), got.toString());
        assertEquals(K05Rule22WiringTest.OK_SCHEMA, got.get(0));
        assertTrue(got.get(1).startsWith("traits|"), got.get(1));
    }

    // ---- revocation epochs under explicit suites ----

    static final long NOW = IntentV2KillTest.NOW;
    static final String ALG = "hybrid-ed25519-ml-dsa-65";

    static Map<String, Object> epochBody(List<String> revoked, long issued) {
        return map("instance_id", "ana", "grant_ref", IntentRevocation.sessionRevocationScope(IntentV2KillTest.SESSION), "epoch", (long) revoked.size(),
            "set_size", (long) revoked.size(), "root", IntentRevocation.revsetRoot(revoked), "issued_at", issued, "not_after", issued + 300_000L);
    }

    static String check(Map<String, Object> epoch, List<String> revoked, Map<String, Object> pins) {
        Object ev = IntentJs.normalize(map("epoch", epoch, "revoked", new java.util.ArrayList<Object>(revoked)));
        return IntentRevocation.checkSessionRevocation(ev, IntentV2KillTest.SESSION, IntentV2KillTest.pub(IntentV2KillTest.REV),
            List.of(IntentV2KillTest.ID_SESSION), NOW, 60_000, null, pins, false, null);
    }

    /** An epoch that names alg ed25519 verifies like one that omits it. */
    @Test void anExplicitEd25519EpochVerifies() {
        List<String> revoked = List.of("pca-intent:zzz");
        Map<String, Object> body = epochBody(revoked, NOW - 10_000);
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", IntentV2KillTest.pub(IntentV2KillTest.REV));
        ep.put("alg", "ed25519");
        ep.put("sig", IntentV2KillTest.sign(IntentV2KillTest.REV,
            Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(body))));
        assertNull(check(ep, revoked, null));
    }

    /** A hybrid epoch verifies only with its alg, its pq_pk equal to the verifier's pin, its Ed25519 sig and its pq_sig. */
    @Test void aHybridEpochNeedsEveryMemberAndThePin() {
        List<String> revoked = List.of("pca-intent:zzz");
        AsymmetricCipherKeyPair pqk = PqChainTest.pqKey();
        String pqpk = PqChainTest.pk(pqk);
        Map<String, Object> signed = epochBody(revoked, NOW - 10_000);
        signed.put("alg", ALG);
        signed.put("pq_pk", pqpk);
        byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(signed));
        Map<String, Object> ep = new LinkedHashMap<>(signed);
        ep.put("guardian", IntentV2KillTest.pub(IntentV2KillTest.REV));
        ep.put("sig", IntentV2KillTest.sign(IntentV2KillTest.REV, msg));
        ep.put("pq_sig", PqChainTest.pqSign(pqk, msg));
        Map<String, Object> pins = map(IntentV2KillTest.pub(IntentV2KillTest.REV), pqpk);
        assertNull(check(ep, revoked, pins));
        assertEquals("revocation epoch signature invalid", check(ep, revoked, null), "no pin: the epoch's own key proves nothing");
        Map<String, Object> noPqSig = new LinkedHashMap<>(ep);
        noPqSig.remove("pq_sig");
        assertEquals("revocation epoch signature invalid", check(noPqSig, revoked, pins));
    }

    // ---- NullSafe ----

    @Test void nullSafeSetsAreReadOnly() {
        java.util.Set<String> s = NullSafe.set(List.of("a", "b"));
        assertEquals(List.of("a", "b"), new java.util.ArrayList<>(s));
        assertThrows(UnsupportedOperationException.class, () -> s.add("c"));
        assertFalse(s.contains(null));
    }

    // ---- Sigstore.namedBy ----

    static byte[] cert(byte[] sigAlg, byte[] serial, byte[] subject, String issuer, byte[] spki) {
        byte[] tbs = seq(withTag(0xa0, integer(2)), withTag(0x02, serial), sigAlg, name(issuer), seq(K05IssuerRsaPssTest.FROM, K05IssuerRsaPssTest.TO), subject, spki);
        return seq(tbs, sigAlg, bits((byte) 0, K05IssuerRsaPssTest.pkcs1(tbs)));
    }

    /** x509_check_issued does not look at the signature algorithm; only a PKCS#1 signature under an rsa-pss key is refused. */
    @Test void anRsaPssSignatureUnderAnRsaPssIssuerIsNamed() throws Exception {
        byte[] pssAlg = K05IssuerRsaPssTest.PSS_SPKI_ALG;
        byte[] issuer = K05IssuerRsaPssTest.rsaSigned(new byte[] {6}, "Int", "Top", K05IssuerRsaPssTest.spki(K05IssuerRsaPssTest.PSS_SPKI_ALG));
        byte[] pssLeaf = cert(pssAlg, new byte[] {5}, name("Sub"), "Int", K05IssuerRsaPssTest.spki(K05IssuerRsaPssTest.RSA_SPKI_ALG));
        assertTrue(K05IssuerRsaPssTest.namedBy(pssLeaf, issuer));
    }

    /** A leaf the strict certificate parser refuses (an INTEGER as a name value) is not named, even though the JDK read it. */
    @Test void aLeafTheStrictParserRefusesIsNotNamed() throws Exception {
        byte[] badName = seq(withTag(0x31, seq(oid("2.5.4.3"), integer(5))));
        byte[] issuer = K05IssuerRsaPssTest.rsaSigned(new byte[] {6}, "Int", "Top", K05IssuerRsaPssTest.spki(K05IssuerRsaPssTest.RSA_SPKI_ALG));
        byte[] spki = K05IssuerRsaPssTest.spki(K05IssuerRsaPssTest.RSA_SPKI_ALG);
        assertTrue(K05IssuerRsaPssTest.namedBy(cert(K05IssuerRsaPssTest.RSA_SHA256, new byte[] {5}, name("Sub"), "Int", spki), issuer), "control");
        assertFalse(K05IssuerRsaPssTest.namedBy(cert(K05IssuerRsaPssTest.RSA_SHA256, new byte[] {5}, badName, "Int", spki), issuer));
    }
}
