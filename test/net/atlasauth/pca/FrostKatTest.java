package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.atlasauth.pca.Frost.FrostCommitResult;
import net.atlasauth.pca.Frost.FrostCommitment;
import net.atlasauth.pca.Frost.FrostKeygenOpts;
import net.atlasauth.pca.Frost.FrostKeygenResult;
import net.atlasauth.pca.Frost.FrostNonces;
import net.atlasauth.pca.Frost.FrostParticipantShare;
import net.atlasauth.pca.Frost.FrostSignOpts;
import net.atlasauth.pca.Frost.FrostSignatureShare;
import net.atlasauth.pca.Frost.VerificationShare;
import org.junit.jupiter.api.Test;

/**
 * RFC 9591 appendix E.1, FROST(Ed25519, SHA-512): the official test vectors (t = 2, n = 3, signers 1 and 3) reproduced byte for byte,
 * plus the one-shot nonce and tamper refusals.
 */
class FrostKatTest {
    static byte[] hex(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static String toHex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static final String GROUP_SECRET = "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304";
    static final String GROUP_PK = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    static final String COEFF1 = "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204";
    static final String MESSAGE = "74657374";
    static final String AGGREGATE = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe" + "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b";

    /** id, share, hidingRandomness, bindingRandomness, hidingNonce, bindingNonce, hidingCommitment, bindingCommitment, sigShare. */
    static final String[][] P = {
        {"1", "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509", "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
         "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501", "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
         "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301", "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
         "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932", "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603"},
        {"3", "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02", "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f",
         "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775", "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
         "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d", "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
         "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552", "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007"},
    };

    static FrostKeygenResult keygen() {
        FrostKeygenOpts o = new FrostKeygenOpts();
        o.secret = hex(GROUP_SECRET);
        o.coefficients = List.of(hex(COEFF1));
        o.identifiers = new long[] {1, 2, 3};
        return Frost.trustedDealerKeygen(2, 3, o);
    }

    static List<FrostCommitment> commitments() {
        List<FrostCommitment> l = new ArrayList<>();
        for (String[] p : P) l.add(new FrostCommitment(Long.parseLong(p[0]), hex(p[6]), hex(p[7])));
        return l;
    }

    static FrostNonces nonces(String[] p) { return new FrostNonces(hex(p[4]), hex(p[5])); }

    @Test void trustedDealerSplitMatchesRfc() {
        FrostKeygenResult kg = keygen();
        assertEquals(GROUP_PK, toHex(kg.groupPublicKey));
        assertEquals(P[0][1], toHex(kg.participantShares.get(0).share));
        assertEquals(P[1][1], toHex(kg.participantShares.get(2).share));
    }

    @Test void roundOneNoncesAndCommitmentsMatchRfc() {
        for (String[] p : P) {
            FrostCommitResult c = Frost.commit(new FrostParticipantShare(Long.parseLong(p[0]), hex(p[1]), new byte[32]), hex(p[2]), hex(p[3]));
            assertEquals(p[4], toHex(c.hidingNonce));
            assertEquals(p[5], toHex(c.bindingNonce));
            assertEquals(p[6], toHex(c.commitment.hiding));
            assertEquals(p[7], toHex(c.commitment.binding));
        }
    }

    @Test void signatureSharesAndAggregateMatchRfc() {
        byte[] group = hex(GROUP_PK), msg = hex(MESSAGE);
        List<FrostCommitment> cs = commitments();
        List<FrostSignatureShare> shares = new ArrayList<>();
        List<VerificationShare> vss = new ArrayList<>();
        for (String[] p : P) {
            FrostSignatureShare s = Frost.sign(Long.parseLong(p[0]), hex(p[1]), group, nonces(p), msg, cs, null);
            assertEquals(p[8], toHex(s.sigShare));
            shares.add(s);
            vss.add(new VerificationShare(Long.parseLong(p[0]), Frost.verifyingShare(hex(p[1]))));
        }
        FrostKeygenResult kg = keygen();
        for (int i = 0; i < 2; i++) {
            assertTrue(Frost.verifySigShare(shares.get(i).identifier, kg.participantShares.get(i == 0 ? 0 : 2).publicKey, cs.get(i), shares.get(i), cs, group, msg));
        }
        byte[] sig = Frost.aggregate(msg, cs, shares, group, null, vss);
        assertEquals(AGGREGATE, toHex(sig));
        assertTrue(EdStrict.verify(group, msg, sig));

        // a tampered share is refused, and so is a share checked under the wrong verification share
        byte[] bad = shares.get(0).sigShare.clone();
        bad[0] ^= 1;
        assertFalse(Frost.verifySigShare(1, vss.get(0).publicKey, cs.get(0), new FrostSignatureShare(1, bad), cs, group, msg));
        assertFalse(Frost.verifySigShare(1, vss.get(1).publicKey, cs.get(0), shares.get(0), cs, group, msg));
        // z + L must not verify alongside z
        BigInteger z = new BigInteger(1, reverse(shares.get(0).sigShare)).add(Frost.L);
        byte[] zl = reverse(z.toByteArray());
        byte[] zl32 = Arrays.copyOf(zl, 32);
        assertFalse(Frost.isCanonicalScalar(zl32));
        assertFalse(Frost.verifySigShare(1, vss.get(0).publicKey, cs.get(0), new FrostSignatureShare(1, zl32), cs, group, msg));
        assertThrows(IllegalArgumentException.class, () -> Frost.aggregate(msg, cs, List.of(shares.get(0), new FrostSignatureShare(3, bad)), group, null, vss));
        assertThrows(IllegalArgumentException.class, () -> Frost.aggregate(msg, cs, shares, group, null, null));
        assertThrows(IllegalArgumentException.class, () -> Frost.aggregate(msg, cs, shares, group, 3, vss));
    }

    static byte[] reverse(byte[] b) {
        byte[] o = new byte[b.length];
        for (int i = 0; i < b.length; i++) o[b.length - 1 - i] = b[i];
        return o;
    }

    /** Fresh, distinct randomness so the nonce registry of the RFC test is not touched. */
    @Test void cosignRoundTripAndRefusals() {
        FrostKeygenOpts o = new FrostKeygenOpts();
        o.secret = hex("0100000000000000000000000000000000000000000000000000000000000000");
        o.coefficients = List.of(hex("0200000000000000000000000000000000000000000000000000000000000000"));
        FrostKeygenResult kg = Frost.trustedDealerKeygen(2, 3, o);
        byte[] msg = "cosign".getBytes();
        byte[] sig = Frost.cosign(kg.groupPublicKey, kg.participantShares.subList(0, 2), msg, 2);
        assertTrue(EdStrict.verify(kg.groupPublicKey, msg, sig));
        assertThrows(IllegalArgumentException.class, () -> Frost.cosign(kg.groupPublicKey, kg.participantShares.subList(0, 1), msg, 2));
        assertThrows(IllegalArgumentException.class, () -> Frost.cosign(kg.groupPublicKey, List.of(), msg, 2));
        assertThrows(IllegalArgumentException.class, () -> Frost.cosign(kg.groupPublicKey, List.of(kg.participantShares.get(0), kg.participantShares.get(0)), msg, 2));
    }

    @Test void nonceIsOneShot() {
        FrostKeygenResult kg = keygen();
        byte[] group = hex(GROUP_PK), msg = "once".getBytes();
        FrostParticipantShare p1 = kg.participantShares.get(0), p2 = kg.participantShares.get(1);
        byte[] r = hex("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1");
        byte[] r2 = hex("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2");
        byte[] r3 = hex("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3");
        byte[] r4 = hex("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4");
        FrostCommitResult c1 = Frost.commit(p1, r, r2), c2 = Frost.commit(p2, r3, r4);
        List<FrostCommitment> cs = List.of(c1.commitment, c2.commitment);
        FrostNonces n1 = c1.nonces();
        Frost.sign(p1.identifier, p1.share, group, n1, msg, cs, null);
        assertTrue(Arrays.equals(n1.hiding, new byte[32])); // zeroised
        assertThrows(IllegalArgumentException.class, () -> Frost.sign(p1.identifier, p1.share, group, n1, msg, cs, null));
        // a fresh array carrying the same nonce value is refused through the commitment registry
        FrostNonces again = Frost.commit(p1, r, r2).nonces();
        assertThrows(IllegalArgumentException.class, () -> Frost.sign(p1.identifier, p1.share, group, again, msg, cs, null));
        // the group key must match the verification shares
        FrostCommitResult c3 = Frost.commit(p2, hex("e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"), hex("f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"));
        FrostSignOpts o = new FrostSignOpts();
        o.verificationShare = p1.publicKey;
        List<FrostCommitment> cs2 = List.of(c1.commitment, c3.commitment);
        assertThrows(IllegalArgumentException.class, () -> Frost.sign(p2.identifier, p2.share, group, c3.nonces(), msg, cs2, o));
    }

    @Test void pointDecodingIsStrict() {
        assertThrows(IllegalArgumentException.class, () -> Frost.decodeSafePoint(new byte[31]));
        byte[] identity = new byte[32];
        identity[0] = 1;
        assertThrows(IllegalArgumentException.class, () -> Frost.decodeSafePoint(identity)); // small order
        byte[] nonCanonicalY = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"); // y = p
        assertThrows(IllegalArgumentException.class, () -> Frost.decodeSafePoint(nonCanonicalY));
        assertArrayEquals(hex(GROUP_PK), Frost.decodeSafePoint(hex(GROUP_PK)).toBytes());
    }
}
