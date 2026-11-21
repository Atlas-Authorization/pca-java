package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Frost.FrostKeygenOpts;
import net.atlasauth.pca.Frost.FrostKeygenResult;
import net.atlasauth.pca.Frost.FrostParticipantShare;
import org.junit.jupiter.api.Test;

/**
 * The signer runner as real operating-system processes: three runners (one share each, configured from a file so no share is on a command line)
 * print one ready line each, and a coordinator in this process signs 2-of-3 through their loopback HTTP endpoints.
 */
class FrostNetRunnerTest {
    private static Map<String, Object> config(FrostParticipantShare p, FrostKeygenResult kg, byte[] policy) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("identifier", IntentJs.ofLong(p.identifier));
        c.put("share", Pca.b64(p.share));
        c.put("groupPublicKey", Pca.b64(kg.groupPublicKey));
        c.put("threshold", IntentJs.ofLong(2));
        c.put("policyAuthorityPublicKey", Pca.b64(policy));
        return c;
    }

    @Test void aBadConfigIsRefusedBeforeAnythingListens() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("identifier", IntentJs.ofLong(1));
        c.put("share", "AAAA");
        c.put("groupPublicKey", "AAAA");
        c.put("threshold", IntentJs.ofLong(2));
        c.put("policyAuthorityPublicKey", "AAAA");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> FrostNetRunner.buildService(c));
        assertEquals("frost-net-runner: field 'share' is not 32-byte canonical base64url", e.getMessage());
    }

    @Test void threeRunnerProcessesSignTwoOfThree() throws Exception {
        FrostKeygenResult kg = Frost.trustedDealerKeygen(2, 3, new FrostKeygenOpts());
        Keys.EdKey policy = Keys.edGenerate();
        byte[] message = "transfer 10 USD to alice".getBytes(StandardCharsets.UTF_8);
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Path dir = Files.createTempDirectory("frost-runner");
        List<Process> procs = new ArrayList<>();
        List<FrostNet.SignerTransport> transports = new ArrayList<>();
        List<Object> shares = new ArrayList<>();
        try {
            for (FrostParticipantShare p : kg.participantShares) {
                Path cfg = dir.resolve("signer-" + p.identifier + ".json");
                Files.write(cfg, Json.stringify(config(p, kg, policy.pub)).getBytes(StandardCharsets.UTF_8));
                Process proc = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"), "net.atlasauth.pca.FrostNetRunner", cfg.toString())
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
                procs.add(proc);
                BufferedReader out = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8));
                String line = out.readLine();
                assertNotNull(line, "the runner printed its ready line");
                assertTrue(line.startsWith(FrostNetRunner.READY_PREFIX), line);
                @SuppressWarnings("unchecked")
                Map<String, Object> ready = (Map<String, Object>) Json.parseLenient(line.substring(FrostNetRunner.READY_PREFIX.length()));
                assertEquals((double) p.identifier, IntentJs.num(ready.get("identifier")));
                transports.add(FrostNet.httpSignerTransport((String) ready.get("url"), p.identifier, 10000.0));
                Map<String, Object> vs = new LinkedHashMap<>();
                vs.put("identifier", p.identifier);
                vs.put("publicKey", p.publicKey);
                shares.add(vs);
            }
            Map<String, Object> co = new LinkedHashMap<>();
            co.put("groupPublicKey", kg.groupPublicKey);
            co.put("threshold", 2);
            co.put("signers", transports);
            co.put("verificationShares", shares);
            Map<String, Object> allowOpts = new LinkedHashMap<>();
            allowOpts.put("message", message);
            allowOpts.put("groupPublicKey", kg.groupPublicKey);
            Map<String, Object> allow = FrostNet.issueAllowToken(policy.seed, allowOpts);
            Map<String, Object> res = new FrostNet.NetworkCoordinator(co).sign(message, allow, null);
            assertTrue(Pca.ed25519Strict(kg.groupPublicKey, message, (byte[]) res.get("signature")));
        } finally {
            for (Process pr : procs) pr.destroy();
            for (Process pr : procs) pr.waitFor();
        }
    }
}
