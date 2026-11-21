package net.atlasauth.pca.scitt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.scitt.DurableTransparencyService.Registration;
import net.atlasauth.pca.scitt.Scitt.ConsistencyProofResult;
import net.atlasauth.pca.scitt.Scitt.ReceiptSignerOpts;
import net.atlasauth.pca.scitt.Scitt.SignStatementOpts;

/**
 * In-memory reference log (it recomputes the Merkle tree on every registration and loses everything on restart): use it to produce
 * receipts for tests and demos, never as a production transparency service. The production log is
 * {@link DurableTransparencyService} over a {@link ScittLogStore}.
 */
public final class TransparencyService {
    private final List<byte[]> statements = new ArrayList<>();
    private final List<byte[]> leafHashes = new ArrayList<>();
    private final ReceiptSignerOpts signer;

    public TransparencyService(ReceiptSignerOpts signer) { this.signer = signer; }

    /** Current number of registered statements. */
    public synchronized long size() { return statements.size(); }

    /** The current Merkle tree root (b64u); the empty-log root for an empty service. */
    public synchronized String root() { return Keys.b64u(Rfc9162.treeHash(leafHashes)); }

    /** The statement leaves (b64u of each Signed Statement) currently in the log, in order. */
    public synchronized List<String> snapshot() {
        List<String> out = new ArrayList<>();
        for (byte[] st : statements) out.add(Keys.b64u(st));
        return out;
    }

    private Registration receiptFor(int index) {
        byte[] root = Rfc9162.treeHash(leafHashes);
        Map<String, Object> proof = Scitt.inclusionProofMap(index, leafHashes.size(), Rfc9162.inclusionPath(leafHashes, index));
        String r = Keys.b64u(root);
        return new Registration(index, Scitt.buildReceipt(r, proof, signer), r, null);
    }

    /** Register an already-signed Signed Statement; append it and return a signed inclusion receipt. */
    public synchronized Registration register(byte[] statement) {
        Scitt.CoseSign1 cose = Scitt.decodeCoseSign1(statement);
        if (cose.payload == null) throw new IllegalArgumentException("scitt: cannot register a statement with a detached payload");
        int index = statements.size();
        statements.add(statement.clone());
        leafHashes.add(Rfc9162.leafHash(statement));
        return receiptFor(index);
    }

    /** Sign {@code payload} as a Signed Statement, register it, and return the statement plus its receipt. */
    public synchronized Registration appendAndReceipt(Object payload, SignStatementOpts stmt) {
        byte[] statement = Scitt.signStatement(payload, stmt);
        Registration r = register(statement);
        return new Registration(r.index, r.receipt, r.root, statement);
    }

    /** Re-issue a receipt for an already-registered statement, against the CURRENT ledger root. */
    public synchronized Registration getReceipt(long index) {
        if (index < 0 || index >= statements.size()) throw new IndexOutOfBoundsException("getReceipt: index out of range");
        return receiptFor((int) index);
    }

    /** An RFC 9162 consistency proof that the log at {@code oldSize} entries is a prefix of the current log. */
    public synchronized ConsistencyProofResult consistencyProof(long oldSize) {
        if (oldSize < 1 || oldSize > statements.size()) throw new IndexOutOfBoundsException("consistencyProof: size out of range");
        List<byte[]> path = Rfc9162.consistencyPath(leafHashes, oldSize);
        return new ConsistencyProofResult(oldSize, statements.size(), Keys.b64u(Rfc9162.treeHash(leafHashes.subList(0, (int) oldSize))), root(),
            Cbor.encode(Arrays.asList((Object) oldSize, (long) statements.size(), new ArrayList<Object>(path))));
    }

    /** Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement). */
    public static Registration registerStatement(byte[] statement, TransparencyService service) { return service.register(statement); }
}
