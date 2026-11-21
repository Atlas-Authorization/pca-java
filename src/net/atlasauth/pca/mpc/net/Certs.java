package net.atlasauth.pca.mpc.net;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Per-run identity material for the TLS mesh: one fresh P-256 key and self-signed certificate per node, generated with the
 * vetted {@code openssl} command line (no hand-rolled crypto, no X.509 encoder of our own). The key lives only on the node that
 * generated it; only the PUBLIC certificates are exchanged and pinned.
 */
public final class Certs {
    private Certs() {}

    /** A node identity: PKCS#8 private key PEM and X.509 certificate PEM. */
    public record Identity(String keyPem, String certPem) {}

    /** Generate a throw-away identity for {@code cn} (valid 2 days). Fails closed when openssl is missing or errors. */
    public static Identity generate(String cn) { return generate(cn, "openssl"); }

    public static Identity generate(String cn, String openssl) {
        if (cn == null || !cn.matches("[A-Za-z0-9._-]{1,64}")) throw new IllegalArgumentException("certs: bad common name");
        Path dir = null;
        try {
            dir = Files.createTempDirectory("pca-mesh-id");
            Path key = dir.resolve("key.pem");
            Path cert = dir.resolve("cert.pem");
            run(openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key.toString());
            run(openssl, "req", "-new", "-x509", "-key", key.toString(), "-subj", "/CN=" + cn, "-days", "2", "-sha256",
                "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth,clientAuth",
                "-out", cert.toString());
            return new Identity(Files.readString(key, StandardCharsets.UTF_8), Files.readString(cert, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("certs: identity generation failed: " + e.getMessage(), e);
        } finally {
            if (dir != null) {
                try (Stream<Path> s = Files.list(dir)) {
                    for (Path p : (Iterable<Path>) s::iterator) Files.deleteIfExists(p);
                    Files.deleteIfExists(dir);
                } catch (IOException ignored) {
                    // best effort: the directory holds only a throw-away key
                }
            }
        }
    }

    private static void run(String... cmd) throws IOException {
        Process p = new ProcessBuilder(List.of(cmd)).redirectErrorStream(true).start();
        byte[] out = p.getInputStream().readAllBytes();
        try {
            if (!p.waitFor(60, TimeUnit.SECONDS)) { p.destroyForcibly(); throw new IOException("openssl timed out"); }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
        if (p.exitValue() != 0) throw new IOException("openssl failed: " + new String(out, StandardCharsets.UTF_8));
    }

    private static byte[] pemBody(String pem, String label) {
        String b = pem.replace("-----BEGIN " + label + "-----", "").replace("-----END " + label + "-----", "").replaceAll("\\s", "");
        if (b.isEmpty() || !pem.contains("-----BEGIN " + label + "-----")) throw new IllegalArgumentException("certs: not a " + label + " PEM");
        return Base64.getDecoder().decode(b);
    }

    public static X509Certificate parseCert(String certPem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pemBody(certPem, "CERTIFICATE")));
        } catch (Exception e) {
            throw new IllegalArgumentException("certs: bad certificate: " + e.getMessage(), e);
        }
    }

    public static PrivateKey parseKey(String keyPem) {
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pemBody(keyPem, "PRIVATE KEY")));
        } catch (Exception e) {
            throw new IllegalArgumentException("certs: bad private key (PKCS#8 EC expected)", e);
        }
    }

    /** SHA-256 fingerprint of a DER certificate, lowercase hex. */
    public static String fingerprint(X509Certificate c) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String fingerprintOf(String certPem) { return fingerprint(parseCert(certPem)); }
}
