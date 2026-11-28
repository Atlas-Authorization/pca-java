package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import net.atlasauth.pca.FrostDkgChannel.DkgChannel;
import net.atlasauth.pca.FrostDkgChannel.DkgChannelError;
import org.junit.jupiter.api.Test;

/**
 * The mutual-TLS DKG node over real loopback links (JSSE, TLS 1.3, pinned certificates): a 2-of-3 ceremony in which every party ends with the
 * same group key, a node that pins the wrong certificate for a peer never links to it, and a plaintext client and a TLS 1.2 client are refused.
 * The certificates are generated per run with the JDK's keytool; nothing is committed.
 */
class FrostDkgTlsNodeTest {
    private static String pem(byte[] der, String type) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der) + "\n-----END " + type + "-----\n";
    }

    /** {keyPem, certPem} of a fresh self-signed EC P-256 identity. */
    private static String[] identity(Path dir, String cn) throws Exception {
        Path ks = dir.resolve(cn + ".p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "k", "-keyalg", "EC", "-keysize", "256", "-sigalg", "SHA256withECDSA",
            "-dname", "CN=" + cn, "-validity", "2", "-storetype", "PKCS12", "-keystore", ks.toString(), "-storepass", "changeit", "-keypass", "changeit")
            .redirectErrorStream(true).start();
        byte[] out = p.getInputStream().readAllBytes();
        assertEquals(0, p.waitFor(), new String(out, StandardCharsets.UTF_8));
        KeyStore k = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ks)) { k.load(in, "changeit".toCharArray()); }
        PrivateKey key = (PrivateKey) k.getKey("k", "changeit".toCharArray());
        X509Certificate cert = (X509Certificate) k.getCertificate("k");
        return new String[] {pem(key.getEncoded(), "PRIVATE KEY"), pem(cert.getEncoded(), "CERTIFICATE")};
    }

    private static FrostDkgTlsNode node(long self, byte[] sid, Map<Long, String[]> ids, Map<Long, String> pins) throws Exception {
        FrostDkgTlsNode.Options o = new FrostDkgTlsNode.Options();
        o.self = self;
        o.sessionId = sid;
        o.keyPem = ids.get(self)[0];
        o.certPem = ids.get(self)[1];
        for (Map.Entry<Long, String> e : pins.entrySet()) if (e.getKey() != self) o.peerCerts.add(new FrostDkgTlsNode.PeerCert(e.getKey(), e.getValue()));
        return FrostDkgTlsNode.start(o);
    }

    @Test void aThreePartyCeremonyOverRealMutualTlsLinks() throws Exception {
        Path dir = Files.createTempDirectory("dkg-tls");
        byte[] sid = new byte[32];
        Arrays.fill(sid, (byte) 7);
        List<Long> ids = List.of(1L, 2L, 3L);
        Map<Long, String[]> idents = new LinkedHashMap<>();
        Map<Long, String> pins = new LinkedHashMap<>();
        for (long id : ids) { idents.put(id, identity(dir, "p" + id)); pins.put(id, idents.get(id)[1]); }
        Map<Long, FrostDkgTlsNode> nodes = new LinkedHashMap<>();
        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            for (long id : ids) nodes.put(id, node(id, sid, idents, pins));
            List<Future<Map<String, Object>>> runs = new ArrayList<>();
            for (long id : ids) {
                List<FrostDkgTlsNode.Address> addrs = new ArrayList<>();
                for (long other : ids) if (other != id) addrs.add(new FrostDkgTlsNode.Address(other, "127.0.0.1", nodes.get(other).port()));
                Callable<Map<String, Object>> job = () -> {
                    DkgChannel ch = nodes.get(id).connect(addrs, 10_000);
                    Map<String, Object> opts = new LinkedHashMap<>();
                    opts.put("t", 2);
                    opts.put("participants", new ArrayList<Object>(ids));
                    opts.put("sessionId", sid);
                    opts.put("timeoutMs", 10_000.0);
                    return FrostDkgChannel.runDkgOverChannel(ch, opts);
                };
                runs.add(pool.submit(job));
            }
            byte[] group = null;
            for (Future<Map<String, Object>> f : runs) {
                @SuppressWarnings("unchecked")
                Map<String, Object> kp = (Map<String, Object>) f.get(60, TimeUnit.SECONDS).get("keyPackage");
                byte[] g = (byte[]) kp.get("groupPublicKey");
                assertNotNull(g);
                if (group == null) group = g; else assertArrayEquals(group, g, "every party ends with the same group key");
            }
        } finally {
            for (FrostDkgTlsNode n : nodes.values()) n.close();
            pool.shutdownNow();
        }
    }

    @Test void aNodeThatPinsTheWrongCertificateForAPeerNeverLinks() throws Exception {
        Path dir = Files.createTempDirectory("dkg-tls");
        byte[] sid = new byte[32];
        Map<Long, String[]> idents = new LinkedHashMap<>();
        idents.put(1L, identity(dir, "a"));
        idents.put(2L, identity(dir, "b"));
        String[] stranger = identity(dir, "c");
        Map<Long, String> goodPins = Map.of(1L, idents.get(1L)[1], 2L, idents.get(2L)[1]);
        Map<Long, String> wrongPins = Map.of(1L, stranger[1], 2L, idents.get(2L)[1]); // node 2 pins a stranger as peer 1
        FrostDkgTlsNode one = node(1, sid, idents, goodPins);
        FrostDkgTlsNode two = node(2, sid, idents, wrongPins);
        try {
            DkgChannelError e = assertThrows(DkgChannelError.class, () -> two.connect(List.of(new FrostDkgTlsNode.Address(1, "127.0.0.1", one.port())), 1500));
            assertEquals("timeout", e.code);
            // an address for a participant that is not a pinned peer is refused outright
            FrostDkgTlsNode other = node(2, sid, idents, goodPins);
            try {
                assertEquals("identity", assertThrows(DkgChannelError.class, () -> other.connect(List.of(new FrostDkgTlsNode.Address(9, "127.0.0.1", 1)), 100)).code);
            } finally {
                other.close();
            }
        } finally {
            one.close();
            two.close();
        }
    }

    @Test void aPlaintextClientAndATls12ClientAreRefused() throws Exception {
        Path dir = Files.createTempDirectory("dkg-tls");
        byte[] sid = new byte[32];
        Map<Long, String[]> idents = new LinkedHashMap<>();
        idents.put(1L, identity(dir, "a"));
        idents.put(2L, identity(dir, "b"));
        FrostDkgTlsNode one = node(1, sid, idents, Map.of(1L, idents.get(1L)[1], 2L, idents.get(2L)[1]));
        try {
            try (Socket s = new Socket("127.0.0.1", one.port())) {
                s.setSoTimeout(5000);
                s.getOutputStream().write("hello\n".getBytes(StandardCharsets.UTF_8));
                s.getOutputStream().flush();
                int r;
                try {
                    do { r = s.getInputStream().read(); } while (r >= 0);
                } catch (SocketTimeoutException e) {
                    throw new AssertionError("the node kept a plaintext connection open");
                } catch (IOException e) {
                    // reset: refused
                }
            }
            SSLContext c12 = SSLContext.getInstance("TLSv1.2");
            c12.init(null, new TrustManager[] {new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
                @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            try (SSLSocket s = (SSLSocket) c12.getSocketFactory().createSocket("127.0.0.1", one.port())) {
                s.setEnabledProtocols(new String[] {"TLSv1.2"});
                s.setSoTimeout(5000);
                assertThrows(IOException.class, s::startHandshake);
            }
        } finally {
            one.close();
        }
    }
}
