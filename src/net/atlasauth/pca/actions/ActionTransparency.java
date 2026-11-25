package net.atlasauth.pca.actions;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Map;
import net.atlasauth.pca.ActionRegistry;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.scitt.Scitt;
import net.atlasauth.pca.scitt.TransparencyService;

/**
 * Append a signed pack to a SCITT transparency log (RFC 9943) and verify the receipt. The statement is a COSE Signed Statement over
 * {@code {ns, version, digest, root, prev}}; a verifier holding the pinned log key and tree root can show that this exact pack version was published.
 */
public final class ActionTransparency {
    private ActionTransparency() {}

    public static final String PACK_STATEMENT_CONTENT_TYPE = "application/pca-action-pack+json";

    /** The payload the registry signs into the log (small: the digest, not the pack). */
    public static Map<String, Object> packStatementPayload(Map<String, Object> p) {
        return J.obj("v", J.n(1), "kind", "pca-action-pack-statement", "ns", p.get("ns"), "version", p.get("version"), "digest", ActionRegistry.packDigest(p), "root", p.get("root"), "prev", p.get("prev"));
    }

    /** What {@link #appendPackToLog} returns. */
    public static final class PackLogEntry {
        public final byte[] statement, receipt;
        public final long index;
        public final String root;
        PackLogEntry(byte[] statement, byte[] receipt, long index, String root) { this.statement = statement; this.receipt = receipt; this.index = index; this.root = root; }
    }

    /** Sign the pack's statement with the registry's COSE key and register it. */
    public static PackLogEntry appendPackToLog(Map<String, Object> pack, TransparencyService service, Scitt.CoseAlg alg, PrivateKey key, String issuer) {
        byte[] statement = Scitt.signStatement(packStatementPayload(pack), new Scitt.SignStatementOpts(alg, key, issuer).subject(pack.get("ns") + "@" + pack.get("version")).contentType(PACK_STATEMENT_CONTENT_TYPE));
        net.atlasauth.pca.scitt.DurableTransparencyService.Registration r = TransparencyService.registerStatement(statement, service);
        return new PackLogEntry(statement, r.receipt, r.index, r.root);
    }

    /** Does the entry prove {@code pack} is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. Never throws. */
    public static boolean verifyPackLogEntry(Map<String, Object> pack, byte[] statement, byte[] receipt, PublicKey registry, PublicKey log, String treeRoot) {
        try {
            Scitt.VerifyReceiptOpts o = new Scitt.VerifyReceiptOpts();
            o.verificationKey = log;
            o.statementKey = registry;
            o.treeRoot = treeRoot;
            return Scitt.verifyReceipt(receipt, statement, o) && statementIsFor(pack, statement);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean statementIsFor(Map<String, Object> pack, byte[] statement) {
        byte[] got = Scitt.statementPayload(statement);
        byte[] want = Json.canonicalize(packStatementPayload(pack)).getBytes(StandardCharsets.UTF_8);
        return Arrays.equals(got, want);
    }
}
