package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Runner for a SINGLE network FROST guardian signer, in its OWN OS process: the piece that makes the "separate trust domain" guarantee real at
 * the process level. Each invocation starts ONE {@link FrostNet.GuardianSignerService} holding EXACTLY ONE FROST share and serves it over loopback
 * HTTP; run n of them (one per guardian) and a quorum is driven by a {@link FrostNet.NetworkCoordinator} in a different process, so no single
 * process ever holds more than one share.
 *
 * <p>The config is a JSON file (the first argument, or the {@code FROST_SIGNER_CONFIG} environment variable) so the secret share never appears in
 * a command line: {@code {identifier, share, groupPublicKey, threshold, policyAuthorityPublicKey, port?, host?}} (bytes base64url). On listen it
 * prints EXACTLY one line to standard output, {@code FROST_SIGNER_READY {"identifier":..,"url":..,"port":..}}, so a parent can read the actual URL
 * (the port is ephemeral unless pinned), and it runs until it is terminated.
 */
public final class FrostNetRunner {
    private FrostNetRunner() {}

    /** The prefix of the one ready line. */
    public static final String READY_PREFIX = "FROST_SIGNER_READY ";

    private static byte[] requireBytes(Object b64, int len, String field) {
        byte[] out = Pca.decodeB64uStrict(b64, len);
        if (out == null) throw new IllegalArgumentException("frost-net-runner: field '" + field + "' is not " + len + "-byte canonical base64url");
        return out;
    }

    /** The signer a config describes (the config's byte fields are 32-byte canonical base64url). */
    public static FrostNet.GuardianSignerService buildService(Map<String, Object> cfg) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("identifier", cfg.get("identifier"));
        o.put("share", requireBytes(cfg.get("share"), 32, "share"));
        o.put("groupPublicKey", requireBytes(cfg.get("groupPublicKey"), 32, "groupPublicKey"));
        o.put("threshold", cfg.get("threshold"));
        o.put("policyAuthorityPublicKey", requireBytes(cfg.get("policyAuthorityPublicKey"), 32, "policyAuthorityPublicKey"));
        return new FrostNet.GuardianSignerService(o);
    }

    /** Starts the signer a config describes (host default 127.0.0.1, port default ephemeral) and prints the ready line to {@code out}. */
    public static FrostNet.SignerHttpServer runSigner(Map<String, Object> cfg, java.io.PrintStream out) throws java.io.IOException {
        FrostNet.GuardianSignerService service = buildService(cfg);
        String host = cfg.get("host") instanceof String ? (String) cfg.get("host") : "127.0.0.1";
        Double port = IntentJs.num(cfg.get("port"));
        FrostNet.SignerHttpServer http = FrostNet.startSignerHttpServer(service, host, port == null ? 0 : (int) (double) port);
        Map<String, Object> ready = new LinkedHashMap<>();
        ready.put("identifier", cfg.get("identifier"));
        ready.put("url", http.url);
        ready.put("port", IntentJs.ofLong(http.port));
        out.print(READY_PREFIX + Json.stringify(ready) + "\n");
        out.flush();
        return http;
    }

    /** {@code java net.atlasauth.pca.FrostNetRunner <config.json>} (or set {@code FROST_SIGNER_CONFIG}). */
    public static void main(String[] args) {
        String path = args.length > 0 ? args[0] : System.getenv("FROST_SIGNER_CONFIG");
        if (path == null) {
            System.err.print("usage: FrostNetRunner <config.json>  (or set FROST_SIGNER_CONFIG)\n");
            System.exit(2);
            return;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> cfg = (Map<String, Object>) Json.parseLenient(new String(Files.readAllBytes(Path.of(path)), StandardCharsets.UTF_8));
            FrostNet.SignerHttpServer http = runSigner(cfg, System.out);
            Runtime.getRuntime().addShutdownHook(new Thread(http::close));
            Thread.currentThread().join(); // until SIGTERM / SIGINT
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.print("frost-net-runner: " + e + "\n");
            System.exit(1);
        }
    }
}
