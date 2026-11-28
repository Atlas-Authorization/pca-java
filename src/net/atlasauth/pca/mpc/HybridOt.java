package net.atlasauth.pca.mpc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;
import net.atlasauth.pca.mpc.Ec.Point;
import net.atlasauth.pca.mpc.Ot.BaseOtFn;
import net.atlasauth.pca.mpc.Ot.BaseOtTamper;
import net.atlasauth.pca.mpc.Ot.OtRandom;

/**
 * Hybrid base OT: the elliptic-curve random OT and the ML-KEM random OT run side by side and BOTH secrets are folded into every
 * transfer key, so the transfer is secure if either the classical or the post-quantum assumption holds. The keys encrypt the
 * messages and a per-message commitment catches an inconsistent sender.
 */
public final class HybridOt {
    private HybridOt() {}

    private static final byte[] TAG_HYBRID_SID = "atlas-pca-mpc/hybrid-ot-sid".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TAG_HYBRID_KEY = "atlas-pca-mpc/hybrid-ot-transfer-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TAG_HYBRID_COMMIT = "atlas-pca-mpc/hybrid-ot-msg-commit".getBytes(StandardCharsets.UTF_8);

    private static byte[] sha256(byte[]... chunks) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            for (byte[] c : chunks) h.update(c);
            return h.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("hybrid-ot: XOR length mismatch");
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    /** A hybrid base OT aborted: the sender's ciphertext is inconsistent with its commitment. */
    public static final class HybridOtAbort extends RuntimeException {
        public HybridOtAbort(String message) { super(message); }
    }

    public static byte[] hybridSessionId(byte[] kemSid, Point ecS) { return sha256(TAG_HYBRID_SID, kemSid, Ec.encodePoint(ecS)); }

    public static byte[] hybridTransferKey(byte[] sid, int index, int slot, byte[] ssEc, byte[] ssKem, int len) {
        if (len < 0 || len > 1 << 20) throw new IllegalArgumentException("hybridTransferKey: length must be an integer in [0, 1 MiB]");
        byte[] out = new byte[len];
        int produced = 0;
        long ctr = 0;
        while (produced < len) {
            byte[] block = sha256(TAG_HYBRID_KEY, sid, Ot.u32(index), new byte[] {(byte) (slot & 1)}, Ot.u32(ctr), ssEc, ssKem);
            for (int k = 0; k < block.length && produced < len; k++) out[produced++] = block[k];
            ctr++;
        }
        return out;
    }

    private static byte[] hybridCommit(byte[] sid, int index, int slot, byte[] msg, byte[] key) {
        return sha256(TAG_HYBRID_COMMIT, sid, Ot.u32(index), new byte[] {(byte) (slot & 1)}, msg, key);
    }

    public record HybridSenderMessage(byte[][][] encrypted, byte[][][] commitments) {}

    public static HybridSenderMessage hybridSenderEncrypt(byte[] sid, byte[][][] messages, byte[][][] ecSecrets, byte[][][] kemSecrets) {
        if (messages.length != ecSecrets.length || messages.length != kemSecrets.length) {
            throw new IllegalArgumentException("hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch");
        }
        byte[][][] encrypted = new byte[messages.length][2][];
        byte[][][] commitments = new byte[messages.length][2][];
        for (int i = 0; i < messages.length; i++) {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.length != m1.length) throw new IllegalArgumentException("hybridSenderEncrypt (index " + i + "): the two messages must be equal length");
            byte[] k0 = hybridTransferKey(sid, i, 0, ecSecrets[i][0], kemSecrets[i][0], m0.length);
            byte[] k1 = hybridTransferKey(sid, i, 1, ecSecrets[i][1], kemSecrets[i][1], m1.length);
            encrypted[i][0] = xor(m0, k0);
            encrypted[i][1] = xor(m1, k1);
            commitments[i][0] = hybridCommit(sid, i, 0, m0, k0);
            commitments[i][1] = hybridCommit(sid, i, 1, m1, k1);
        }
        return new HybridSenderMessage(encrypted, commitments);
    }

    public static byte[][] hybridReceiverRecover(byte[] sid, int[] choices, HybridSenderMessage sender, byte[][] ecRecv, byte[][] kemRecv) {
        int n = choices.length;
        if (sender.encrypted().length != n || sender.commitments().length != n || ecRecv.length != n || kemRecv.length != n) {
            throw new IllegalArgumentException("hybridReceiverRecover: length mismatch");
        }
        byte[][] received = new byte[n][];
        for (int i = 0; i < n; i++) {
            int c = choices[i] & 1;
            byte[] e = sender.encrypted()[i][c];
            byte[] key = hybridTransferKey(sid, i, c, ecRecv[i], kemRecv[i], e.length);
            byte[] m = xor(e, key);
            if (!MessageDigest.isEqual(hybridCommit(sid, i, c, m, key), sender.commitments()[i][c])) {
                throw new HybridOtAbort("hybrid base OT (index " + i + "): sender ciphertext inconsistent with its commitment; aborting");
            }
            received[i] = m;
        }
        return received;
    }

    /** TEST-ONLY injection points (null = honest). */
    public static final class HybridBaseOtTamper {
        public BaseOtTamper ec;
        public KemOt.KemMalTamper kem;
        public Consumer<byte[][][]> tamperEncrypted;
    }

    public record HybridBaseOtTranscript(byte[] sid, Point ecS, byte[] kemSid, byte[][][] encrypted, byte[][][] commitments) {}

    public record HybridBaseOtResult(byte[][] received, HybridBaseOtTranscript transcript) {}

    public static HybridBaseOtResult hybridBaseOT(byte[][][] messages, int[] choices, OtRandom rng, HybridBaseOtTamper tamper) {
        if (rng == null) rng = Ot.secureOtRandom();
        if (messages.length != choices.length) throw new IllegalArgumentException("hybridBaseOT: messages/choices length mismatch");
        Ot.MalRandomOtResult ec = Ot.malBaseRandomOT(choices, rng, tamper == null ? null : tamper.ec, null);
        KemOt.KemBaseOtMalRandomResult kem = KemOt.kemBaseOtMalRandom(choices, rng, tamper == null ? null : tamper.kem);
        byte[] sid = hybridSessionId(kem.sid(), ec.S());
        HybridSenderMessage sender = hybridSenderEncrypt(sid, messages, ec.senderPads(), kem.senderSecrets());
        if (tamper != null && tamper.tamperEncrypted != null) tamper.tamperEncrypted.accept(sender.encrypted());
        byte[][] received = hybridReceiverRecover(sid, choices, sender, ec.recvPads(), kem.recvSecrets());
        return new HybridBaseOtResult(received, new HybridBaseOtTranscript(sid, ec.S(), kem.sid(), sender.encrypted(), sender.commitments()));
    }

    /** The hybrid base OT as a pluggable base OT for {@link Ot.OtChannel}. */
    public static BaseOtFn withHybridBaseOt() { return (m, c, r) -> hybridBaseOT(m, c, r, null).received(); }
}
