package net.atlasauth.pca.mpc;

import net.atlasauth.pca.Json;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;
import net.atlasauth.pca.mpc.Ot.BaseOtFn;
import net.atlasauth.pca.mpc.Ot.OtRandom;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;

/**
 * Post-quantum base OT from ML-KEM-768 (FIPS 203): the receiver publishes a public-key pair with a known secret key for only
 * its chosen slot, the sender encapsulates to both and pads each message with the shared secret. Variants: the semi-honest
 * transfer ({@link #kemBaseOT}), the commit-then-open malicious-secure transfer with a session id ({@link #kemBaseOtMal}), and
 * the random-OT form that outputs fixed-width secrets for the hybrid base OT ({@link #kemBaseOtMalRandom}).
 */
public final class KemOt {
    private KemOt() {}

    private static final byte[] TAG_KEMOT = utf8("atlas-pca-mpc/kem-ot-pad");
    private static final byte[] TAG_KEMOT_COMMIT = utf8("atlas-pca-mpc/kem-ot-commit");
    private static final byte[] TAG_KEMOT_SID = utf8("atlas-pca-mpc/kem-ot-sid");
    private static final byte[] TAG_KEMOT_MALPAD = utf8("atlas-pca-mpc/kem-ot-mal-pad");
    private static final byte[] TAG_KEMOT_MALSECRET = utf8("atlas-pca-mpc/kem-ot-mal-secret");
    private static final int NONCE_BYTES = 32;
    public static final int KEM_OT_SECRET_BYTES = 32;

    private static byte[] utf8(String s) { return Json.utf8(s); }

    private static byte[] sha256(byte[]... chunks) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            for (byte[] c : chunks) h.update(c);
            return h.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] u32(long x) { return Ot.u32(x); }

    private static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("kem-ot: XOR length mismatch");
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    private static boolean ctEqual(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static byte[] expand(byte[] tag, byte[][] prefix, long index, int slot, byte[] sharedSecret, int len) {
        byte[] out = new byte[len];
        int produced = 0;
        long ctr = 0;
        while (produced < len) {
            List<byte[]> parts = new ArrayList<>();
            parts.add(tag);
            for (byte[] p : prefix) parts.add(p);
            parts.add(u32(index));
            parts.add(new byte[] {(byte) (slot & 1)});
            parts.add(u32(ctr));
            parts.add(sharedSecret);
            byte[] block = sha256(parts.toArray(new byte[0][]));
            for (int k = 0; k < block.length && produced < len; k++) out[produced++] = block[k];
            ctr++;
        }
        return out;
    }

    /** Pad of {@code len} bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode. */
    public static byte[] kemOtPad(int index, int slot, byte[] sharedSecret, int len) {
        if (len < 0 || len > 1 << 20) throw new IllegalArgumentException("kemOtPad: length must be an integer in [0, 1 MiB]");
        return expand(TAG_KEMOT, new byte[0][], index, slot, sharedSecret, len);
    }

    /** Receiver state of the semi-honest transfer. */
    public record KemOtReceiverState(int[] choices, MLKEMPrivateKeyParameters[] secretKeys) {}

    public record KemOtReceiverMessage(byte[][][] publicKeys) {}

    public record KemOtSenderMessage(byte[][][] ciphertexts, byte[][][] encrypted) {}

    public record KemBaseOtTranscript(byte[][][] publicKeys, byte[][][] ciphertexts, byte[][][] encrypted) {}

    public record KemBaseOtResult(byte[][] received, KemBaseOtTranscript transcript) {}

    public record ReceiverStep(KemOtReceiverMessage message, KemOtReceiverState state) {}

    public static ReceiverStep kemBaseOtReceive(int[] choices, OtRandom rng) {
        if (rng == null) rng = Ot.secureOtRandom();
        byte[][][] publicKeys = new byte[choices.length][2][];
        MLKEMPrivateKeyParameters[] secretKeys = new MLKEMPrivateKeyParameters[choices.length];
        int[] retained = new int[choices.length];
        for (int i = 0; i < choices.length; i++) {
            int c = choices[i] & 1;
            MlKem768.KeyPair chosen = MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES));
            MlKem768.KeyPair other = MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES));
            publicKeys[i][0] = c == 0 ? chosen.publicKey() : other.publicKey();
            publicKeys[i][1] = c == 0 ? other.publicKey() : chosen.publicKey();
            secretKeys[i] = chosen.secretKey();
            retained[i] = c;
        }
        return new ReceiverStep(new KemOtReceiverMessage(publicKeys), new KemOtReceiverState(retained, secretKeys));
    }

    public static KemOtSenderMessage kemBaseOtSend(byte[][][] messages, KemOtReceiverMessage receiverMessage, OtRandom rng) {
        if (rng == null) rng = Ot.secureOtRandom();
        byte[][][] publicKeys = receiverMessage.publicKeys();
        if (messages.length != publicKeys.length) throw new IllegalArgumentException("kemBaseOtSend: messages/publicKeys length mismatch");
        byte[][][] cts = new byte[messages.length][2][];
        byte[][][] encrypted = new byte[messages.length][2][];
        for (int i = 0; i < messages.length; i++) {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.length != m1.length) throw new IllegalArgumentException("kemBaseOtSend (index " + i + "): the two messages must be equal length");
            MlKem768.Encapsulation e0 = MlKem768.encapsulate(publicKeys[i][0], rng.bytes(MlKem768.MSG_BYTES));
            MlKem768.Encapsulation e1 = MlKem768.encapsulate(publicKeys[i][1], rng.bytes(MlKem768.MSG_BYTES));
            cts[i][0] = e0.cipherText();
            cts[i][1] = e1.cipherText();
            encrypted[i][0] = xor(m0, kemOtPad(i, 0, e0.sharedSecret(), m0.length));
            encrypted[i][1] = xor(m1, kemOtPad(i, 1, e1.sharedSecret(), m1.length));
        }
        return new KemOtSenderMessage(cts, encrypted);
    }

    public static byte[][] kemBaseOtOpen(KemOtReceiverState state, KemOtSenderMessage senderMessage) {
        int n = state.choices().length;
        if (senderMessage.ciphertexts().length != n || senderMessage.encrypted().length != n) throw new IllegalArgumentException("kemBaseOtOpen: transcript/state length mismatch");
        byte[][] received = new byte[n][];
        for (int i = 0; i < n; i++) {
            int c = state.choices()[i] & 1;
            byte[] ss = MlKem768.decapsulate(senderMessage.ciphertexts()[i][c], state.secretKeys()[i]);
            byte[] e = senderMessage.encrypted()[i][c];
            received[i] = xor(e, kemOtPad(i, c, ss, e.length));
        }
        return received;
    }

    public static KemBaseOtResult kemBaseOT(byte[][][] messages, int[] choices, OtRandom rng) {
        if (rng == null) rng = Ot.secureOtRandom();
        if (messages.length != choices.length) throw new IllegalArgumentException("kemBaseOT: messages/choices length mismatch");
        ReceiverStep r = kemBaseOtReceive(choices, rng);
        KemOtSenderMessage s = kemBaseOtSend(messages, r.message(), rng);
        byte[][] received = kemBaseOtOpen(r.state(), s);
        return new KemBaseOtResult(received, new KemBaseOtTranscript(r.message().publicKeys(), s.ciphertexts(), s.encrypted()));
    }

    /** The semi-honest KEM OT as a pluggable base OT for {@link Ot.OtChannel}. */
    public static BaseOtFn withKemBaseOt() { return (m, c, r) -> kemBaseOT(m, c, r).received(); }

    // ---- malicious-secure (commit-then-open, session id) ----

    /** A KEM base OT aborted: the opened keys do not match the receiver's commitment. */
    public static final class KemBaseOtAbort extends RuntimeException {
        public KemBaseOtAbort(String message) { super(message); }
    }

    private static byte[] kemMalCommit(byte[] rn, int index, byte[] pk0, byte[] pk1) { return sha256(TAG_KEMOT_COMMIT, rn, u32(index), pk0, pk1); }

    private static byte[] kemMalSid(byte[] rn, byte[] sn) { return sha256(TAG_KEMOT_SID, rn, sn); }

    private static byte[] kemOtMalPad(byte[] sid, byte[] com, int index, int slot, byte[] ss, int len) {
        return expand(TAG_KEMOT_MALPAD, new byte[][] {sid, com}, index, slot, ss, len);
    }

    private static byte[] kemOtMalSecret(byte[] sid, byte[] com, int index, int slot, byte[] ss) {
        byte[] h = sha256(TAG_KEMOT_MALSECRET, sid, com, u32(index), new byte[] {(byte) (slot & 1)}, ss);
        return java.util.Arrays.copyOf(h, KEM_OT_SECRET_BYTES);
    }

    public record KemMalCommitMessage(byte[] rn, byte[][] commitments) {}

    public record KemMalOpenMessage(byte[][][] publicKeys) {}

    public record KemMalSenderNonce(byte[] sn) {}

    public record KemMalSenderMessage(byte[][][] ciphertexts, byte[][][] encrypted) {}

    public record KemMalReceiverState(int[] choices, MLKEMPrivateKeyParameters[] secretKeys, byte[][][] publicKeys, byte[] rn) {}

    public record KemMalTranscript(byte[] rn, byte[][] commitments, byte[] sn, byte[][][] publicKeys, byte[][][] ciphertexts, byte[][][] encrypted) {}

    public record KemBaseOtMalResult(byte[][] received, KemMalTranscript transcript) {}

    /** TEST-ONLY injection points for a malicious sender or receiver (null = honest). */
    public static final class KemMalTamper {
        public Consumer<byte[][][]> tamperOpenedKeys;
        public UnaryOperator<byte[]> tamperReceiverSid;
    }

    public record CommitStep(KemMalCommitMessage message, KemMalReceiverState state) {}

    public static CommitStep kemBaseOtMalCommit(int[] choices, OtRandom rng) {
        if (rng == null) rng = Ot.secureOtRandom();
        byte[] rn = rng.bytes(NONCE_BYTES);
        byte[][][] publicKeys = new byte[choices.length][2][];
        MLKEMPrivateKeyParameters[] secretKeys = new MLKEMPrivateKeyParameters[choices.length];
        int[] retained = new int[choices.length];
        byte[][] commitments = new byte[choices.length][];
        for (int i = 0; i < choices.length; i++) {
            int c = choices[i] & 1;
            MlKem768.KeyPair chosen = MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES));
            MlKem768.KeyPair other = MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES));
            publicKeys[i][0] = c == 0 ? chosen.publicKey() : other.publicKey();
            publicKeys[i][1] = c == 0 ? other.publicKey() : chosen.publicKey();
            secretKeys[i] = chosen.secretKey();
            retained[i] = c;
            commitments[i] = kemMalCommit(rn, i, publicKeys[i][0], publicKeys[i][1]);
        }
        return new CommitStep(new KemMalCommitMessage(rn, commitments), new KemMalReceiverState(retained, secretKeys, publicKeys, rn));
    }

    public static KemMalSenderNonce kemBaseOtMalSenderNonce(OtRandom rng) {
        if (rng == null) rng = Ot.secureOtRandom();
        return new KemMalSenderNonce(rng.bytes(NONCE_BYTES));
    }

    /** The receiver's opening: a copy of its public-key pairs. */
    public static KemMalOpenMessage kemBaseOtMalOpen(KemMalReceiverState state) {
        byte[][][] pk = new byte[state.publicKeys().length][2][];
        for (int i = 0; i < pk.length; i++) {
            pk[i][0] = state.publicKeys()[i][0];
            pk[i][1] = state.publicKeys()[i][1];
        }
        return new KemMalOpenMessage(pk);
    }

    public static KemMalSenderMessage kemBaseOtMalSend(byte[][][] messages, KemMalCommitMessage commit, KemMalSenderNonce senderNonce, KemMalOpenMessage opening, OtRandom rng) {
        if (rng == null) rng = Ot.secureOtRandom();
        byte[][][] publicKeys = opening.publicKeys();
        if (messages.length != publicKeys.length || commit.commitments().length != publicKeys.length) {
            throw new IllegalArgumentException("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch");
        }
        byte[] sid = kemMalSid(commit.rn(), senderNonce.sn());
        byte[][][] cts = new byte[messages.length][2][];
        byte[][][] encrypted = new byte[messages.length][2][];
        for (int i = 0; i < messages.length; i++) {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.length != m1.length) throw new IllegalArgumentException("kemBaseOtMalSend (index " + i + "): the two messages must be equal length");
            byte[] com = kemMalCommit(commit.rn(), i, publicKeys[i][0], publicKeys[i][1]);
            if (!ctEqual(com, commit.commitments()[i])) throw new KemBaseOtAbort("kem base OT (index " + i + "): opened public keys do not match the receiver's commitment; aborting");
            MlKem768.Encapsulation e0 = MlKem768.encapsulate(publicKeys[i][0], rng.bytes(MlKem768.MSG_BYTES));
            MlKem768.Encapsulation e1 = MlKem768.encapsulate(publicKeys[i][1], rng.bytes(MlKem768.MSG_BYTES));
            cts[i][0] = e0.cipherText();
            cts[i][1] = e1.cipherText();
            encrypted[i][0] = xor(m0, kemOtMalPad(sid, com, i, 0, e0.sharedSecret(), m0.length));
            encrypted[i][1] = xor(m1, kemOtMalPad(sid, com, i, 1, e1.sharedSecret(), m1.length));
        }
        return new KemMalSenderMessage(cts, encrypted);
    }

    public static byte[][] kemBaseOtMalRecover(KemMalReceiverState state, KemMalSenderNonce senderNonce, KemMalSenderMessage senderMessage, KemMalTamper tamper) {
        int n = state.choices().length;
        if (senderMessage.ciphertexts().length != n || senderMessage.encrypted().length != n) throw new IllegalArgumentException("kemBaseOtMalRecover: transcript/state length mismatch");
        byte[] sid = kemMalSid(state.rn(), senderNonce.sn());
        if (tamper != null && tamper.tamperReceiverSid != null) sid = tamper.tamperReceiverSid.apply(sid);
        byte[][] received = new byte[n][];
        for (int i = 0; i < n; i++) {
            int c = state.choices()[i] & 1;
            byte[] com = kemMalCommit(state.rn(), i, state.publicKeys()[i][0], state.publicKeys()[i][1]);
            byte[] ss = MlKem768.decapsulate(senderMessage.ciphertexts()[i][c], state.secretKeys()[i]);
            byte[] e = senderMessage.encrypted()[i][c];
            received[i] = xor(e, kemOtMalPad(sid, com, i, c, ss, e.length));
        }
        return received;
    }

    public static KemBaseOtMalResult kemBaseOtMal(byte[][][] messages, int[] choices, OtRandom rng, KemMalTamper tamper) {
        if (rng == null) rng = Ot.secureOtRandom();
        if (messages.length != choices.length) throw new IllegalArgumentException("kemBaseOtMal: messages/choices length mismatch");
        CommitStep cs = kemBaseOtMalCommit(choices, rng);
        KemMalSenderNonce nonce = kemBaseOtMalSenderNonce(rng);
        KemMalOpenMessage opening = kemBaseOtMalOpen(cs.state());
        if (tamper != null && tamper.tamperOpenedKeys != null) tamper.tamperOpenedKeys.accept(opening.publicKeys());
        KemMalSenderMessage sm = kemBaseOtMalSend(messages, cs.message(), nonce, opening, rng);
        byte[][] received = kemBaseOtMalRecover(cs.state(), nonce, sm, tamper);
        return new KemBaseOtMalResult(received, new KemMalTranscript(cs.message().rn(), cs.message().commitments(), nonce.sn(), opening.publicKeys(), sm.ciphertexts(), sm.encrypted()));
    }

    /** The malicious-secure KEM OT as a pluggable base OT for {@link Ot.OtChannel}. */
    public static BaseOtFn withKemBaseOtMal() { return (m, c, r) -> kemBaseOtMal(m, c, r, null).received(); }

    // ---- random-OT form (fixed-width secrets, for the hybrid base OT) ----

    public record KemMalRandomSenderMessage(byte[][][] ciphertexts, byte[][][] senderSecrets) {}

    public record KemMalRandomTranscript(byte[] rn, byte[][] commitments, byte[] sn, byte[][][] publicKeys, byte[][][] ciphertexts) {}

    public record KemBaseOtMalRandomResult(byte[][][] senderSecrets, byte[][] recvSecrets, byte[] sid, KemMalRandomTranscript transcript) {}

    public static KemMalRandomSenderMessage kemBaseOtMalRandomSend(KemMalCommitMessage commit, KemMalSenderNonce senderNonce, KemMalOpenMessage opening, OtRandom rng) {
        if (rng == null) rng = Ot.secureOtRandom();
        byte[][][] publicKeys = opening.publicKeys();
        if (commit.commitments().length != publicKeys.length) throw new IllegalArgumentException("kemBaseOtMalRandomSend: commitments/publicKeys length mismatch");
        byte[] sid = kemMalSid(commit.rn(), senderNonce.sn());
        byte[][][] cts = new byte[publicKeys.length][2][];
        byte[][][] secrets = new byte[publicKeys.length][2][];
        for (int i = 0; i < publicKeys.length; i++) {
            byte[] com = kemMalCommit(commit.rn(), i, publicKeys[i][0], publicKeys[i][1]);
            if (!ctEqual(com, commit.commitments()[i])) throw new KemBaseOtAbort("kem base OT (index " + i + "): opened public keys do not match the receiver's commitment; aborting");
            MlKem768.Encapsulation e0 = MlKem768.encapsulate(publicKeys[i][0], rng.bytes(MlKem768.MSG_BYTES));
            MlKem768.Encapsulation e1 = MlKem768.encapsulate(publicKeys[i][1], rng.bytes(MlKem768.MSG_BYTES));
            cts[i][0] = e0.cipherText();
            cts[i][1] = e1.cipherText();
            secrets[i][0] = kemOtMalSecret(sid, com, i, 0, e0.sharedSecret());
            secrets[i][1] = kemOtMalSecret(sid, com, i, 1, e1.sharedSecret());
        }
        return new KemMalRandomSenderMessage(cts, secrets);
    }

    public static byte[][] kemBaseOtMalRandomRecover(KemMalReceiverState state, KemMalSenderNonce senderNonce, KemMalRandomSenderMessage senderMessage, KemMalTamper tamper) {
        int n = state.choices().length;
        if (senderMessage.ciphertexts().length != n) throw new IllegalArgumentException("kemBaseOtMalRandomRecover: transcript/state length mismatch");
        byte[] sid = kemMalSid(state.rn(), senderNonce.sn());
        if (tamper != null && tamper.tamperReceiverSid != null) sid = tamper.tamperReceiverSid.apply(sid);
        byte[][] recv = new byte[n][];
        for (int i = 0; i < n; i++) {
            int c = state.choices()[i] & 1;
            byte[] com = kemMalCommit(state.rn(), i, state.publicKeys()[i][0], state.publicKeys()[i][1]);
            byte[] ss = MlKem768.decapsulate(senderMessage.ciphertexts()[i][c], state.secretKeys()[i]);
            recv[i] = kemOtMalSecret(sid, com, i, c, ss);
        }
        return recv;
    }

    public static KemBaseOtMalRandomResult kemBaseOtMalRandom(int[] choices, OtRandom rng, KemMalTamper tamper) {
        if (rng == null) rng = Ot.secureOtRandom();
        CommitStep cs = kemBaseOtMalCommit(choices, rng);
        KemMalSenderNonce nonce = kemBaseOtMalSenderNonce(rng);
        KemMalOpenMessage opening = kemBaseOtMalOpen(cs.state());
        if (tamper != null && tamper.tamperOpenedKeys != null) tamper.tamperOpenedKeys.accept(opening.publicKeys());
        KemMalRandomSenderMessage sm = kemBaseOtMalRandomSend(cs.message(), nonce, opening, rng);
        byte[][] recv = kemBaseOtMalRandomRecover(cs.state(), nonce, sm, tamper);
        return new KemBaseOtMalRandomResult(sm.senderSecrets(), recv, kemMalSid(cs.message().rn(), nonce.sn()),
            new KemMalRandomTranscript(cs.message().rn(), cs.message().commitments(), nonce.sn(), opening.publicKeys(), sm.ciphertexts()));
    }
}
