package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Frost.FrostKeygenOpts;
import net.atlasauth.pca.Frost.FrostKeygenResult;
import net.atlasauth.pca.Frost.FrostParticipantShare;
import org.junit.jupiter.api.Test;

/** A 2-of-3 network signing session over the loopback HTTP transport: the aggregate is an ordinary Ed25519 signature under the group key. */
class FrostNetHttpTest {
    @Test void aSessionOverHttpSignsAndAnUnauthorizedOneRefuses() throws Exception {
        FrostKeygenResult kg = Frost.trustedDealerKeygen(2, 3, new FrostKeygenOpts());
        Keys.EdKey policy = Keys.edGenerate();
        byte[] message = "transfer 10 USD to alice".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        List<FrostNet.SignerHttpServer> servers = new ArrayList<>();
        List<FrostNet.SignerTransport> transports = new ArrayList<>();
        List<Object> shares = new ArrayList<>();
        try {
            for (FrostParticipantShare p : kg.participantShares) {
                Map<String, Object> o = new LinkedHashMap<>();
                o.put("identifier", p.identifier); o.put("share", p.share); o.put("groupPublicKey", kg.groupPublicKey);
                o.put("threshold", 2); o.put("policyAuthorityPublicKey", policy.pub);
                FrostNet.SignerHttpServer srv = FrostNet.startSignerHttpServer(new FrostNet.GuardianSignerService(o), "127.0.0.1", 0);
                servers.add(srv);
                transports.add(FrostNet.httpSignerTransport(srv.url, p.identifier, 5000.0));
                Map<String, Object> vs = new LinkedHashMap<>();
                vs.put("identifier", p.identifier); vs.put("publicKey", p.publicKey);
                shares.add(vs);
            }
            Map<String, Object> co = new LinkedHashMap<>();
            co.put("groupPublicKey", kg.groupPublicKey); co.put("threshold", 2); co.put("signers", transports); co.put("verificationShares", shares);
            FrostNet.NetworkCoordinator coordinator = new FrostNet.NetworkCoordinator(co);
            Map<String, Object> allowOpts = new LinkedHashMap<>();
            allowOpts.put("message", message); allowOpts.put("groupPublicKey", kg.groupPublicKey);
            Map<String, Object> allow = FrostNet.issueAllowToken(policy.seed, allowOpts);
            Map<String, Object> res = coordinator.sign(message, allow, null);
            assertTrue(Pca.ed25519Strict(kg.groupPublicKey, message, (byte[]) res.get("signature")));
            assertEquals(2, ((List<?>) res.get("signers")).size());
            // a token for another action is refused by every signer: the coordinator cannot sign without the policy authority
            Map<String, Object> otherOpts = new LinkedHashMap<>(allowOpts);
            otherOpts.put("message", "something else".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Map<String, Object> other = FrostNet.issueAllowToken(policy.seed, otherOpts);
            try {
                coordinator.sign(message, other, null);
                throw new AssertionError("a token for another message must not sign");
            } catch (FrostNet.CoordinatorError e) {
                assertTrue(e.getMessage().contains("round 2"));
            }
        } finally {
            for (FrostNet.SignerHttpServer s : servers) s.close();
        }
    }
}
