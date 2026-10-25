package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.junit.jupiter.api.Test;

/**
 * 0.4.2 mutation kills for LessNative.java and the LESS / PQ seams of Pq.java: the signature-length rule on both sides of
 * every bound, the library search path, the FFM verify on the known answers of packages/pca/conformance/less-vectors.json
 * (valid, forged, wrong key, empty message) and the raw / base64url PQ verify entry points with each argument refused.
 * The LESS assertions run when LessNative is available (Java 22+ with libatlas_less, as in CI); the availability itself is
 * pinned to the environment (a Java 22+ runtime with a readable candidate library MUST load it).
 */
public class K042WbPcaMiscLessTest {
    static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    static Map<String, Object> VECTORS;

    @SuppressWarnings("unchecked")
    static synchronized Map<String, Object> vectors() throws Exception {
        if (VECTORS == null) VECTORS = (Map<String, Object>) Json.parseLenient(new String(Files.readAllBytes(LessNativeTest.vectors()), StandardCharsets.UTF_8));
        return VECTORS;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> vector(String name) throws Exception {
        for (Object o : (List<Object>) vectors().get("vectors")) if (name.equals(((Map<String, Object>) o).get("name"))) return (Map<String, Object>) o;
        throw new IllegalStateException(name);
    }

    @SuppressWarnings("unchecked")
    static byte[] key(String k, String member) throws Exception {
        return Pca.decodeB64uStrict(((Map<String, Object>) ((Map<String, Object>) vectors().get("keys")).get(k)).get(member), -1);
    }

    static byte[] bytes(Map<String, Object> v, String member) { return Pca.decodeB64uStrict(v.get(member), -1); }

    // ---------------------------------------------------------------- the signature-length rule (pure arithmetic)

    @Test
    void sigLenOkEveryBound() {
        assertEquals(97484, LessNative.PUBLIC_KEY_BYTES);
        assertEquals(1153, LessNative.SIGNATURE_MIN_BYTES);
        assertEquals(1329, LessNative.SIGNATURE_MAX_BYTES);
        List<Integer> ok = new ArrayList<>();
        for (int n = -20; n <= 1400; n++) if (LessNative.sigLenOk(n)) ok.add(n);
        List<Integer> want = new ArrayList<>();
        for (int n = 1153; n <= 1329; n += 16) want.add(n);
        assertEquals(want, ok);
        assertEquals(12, ok.size());
        assertTrue(LessNative.sigLenOk(1153));
        assertTrue(LessNative.sigLenOk(1329));
        assertTrue(LessNative.sigLenOk(1313));
        assertFalse(LessNative.sigLenOk(1152));
        assertFalse(LessNative.sigLenOk(1330));
        assertFalse(LessNative.sigLenOk(1345));
        assertFalse(LessNative.sigLenOk(1137));
        assertFalse(LessNative.sigLenOk(1328));
        assertFalse(LessNative.sigLenOk(1154));
        assertFalse(LessNative.sigLenOk(0));
        assertFalse(LessNative.sigLenOk(Integer.MIN_VALUE));
        assertFalse(LessNative.sigLenOk(Integer.MAX_VALUE));
        // the primitive's rule delegates to it; the fixed-length primitives are exact
        assertTrue(Pq.Prim.LESS_CAT1.sigLenOk(1153));
        assertTrue(Pq.Prim.LESS_CAT1.sigLenOk(1281));
        assertFalse(Pq.Prim.LESS_CAT1.sigLenOk(1154));
        assertFalse(Pq.Prim.LESS_CAT1.sigLenOk(1330));
        assertTrue(Pq.Prim.ML_DSA_65.sigLenOk(3309));
        assertFalse(Pq.Prim.ML_DSA_65.sigLenOk(3310));
        assertFalse(Pq.Prim.ML_DSA_65.sigLenOk(1313));
    }

    // ---------------------------------------------------------------- the library search path

    @Test
    void candidatesAreEnvThenRepositoryBuild() {
        List<Path> want = new ArrayList<>();
        String env = System.getenv("ATLAS_PCA_LIBLESS");
        if (env == null || env.isEmpty()) env = System.getProperty("atlas.pca.libless", "");
        for (String p : env.split(File.pathSeparator)) if (!p.isEmpty()) want.add(Paths.get(p));
        Path build = null;
        for (Path d = Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath(); d != null; d = d.getParent()) {
            Path b = d.resolve("sdks").resolve("pca-less-c").resolve("build");
            if (Files.isDirectory(b)) { build = b; break; }
        }
        if (build != null) for (String n : List.of("libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll")) want.add(build.resolve(n));
        List<Path> got = LessNative.candidates();
        assertEquals(want, got);
        // the repository's build directory, when this layout has one (the monorepo after a local build; the public repo's
        // CI rebuilds the layout without it and passes the library through ATLAS_PCA_LIBLESS instead)
        if (build != null) assertBuildTail(build, got);
        if (env != null && !env.isEmpty() && !env.contains(File.pathSeparator)) assertEquals(Paths.get(env), got.get(0));
        // a fresh list per call (callers may not share it)
        assertNotSame(got, LessNative.candidates());
    }

    static void assertBuildTail(Path build, List<Path> got) {
        assertTrue(got.size() >= 3);
        assertEquals(build.resolve("libatlas_less.so"), got.get(got.size() - 3));
        assertEquals(build.resolve("libatlas_less.dylib"), got.get(got.size() - 2));
        assertEquals(build.resolve("atlas_less.dll"), got.get(got.size() - 1));
        assertTrue(got.get(got.size() - 1).isAbsolute());
    }

    /**
     * The upward search, layout-independent: a synthetic tree {@code <tmp>/sdks/pca-less-c/build} with user.dir two levels
     * below it. The nearest build directory wins (the search stops there), a plain FILE named build is skipped, and the
     * environment entries stay first.
     */
    @Test
    void candidatesSearchUpwardForTheNearestBuildDirectory() throws Exception {
        Path root = Files.createTempDirectory("k042-less").toAbsolutePath();
        String dir = System.getProperty("user.dir");
        try {
            Path outer = Files.createDirectories(root.resolve("sdks").resolve("pca-less-c").resolve("build"));
            Path mid = root.resolve("a");
            Path inner = Files.createDirectories(mid.resolve("sdks").resolve("pca-less-c").resolve("build"));
            Path cwd = Files.createDirectories(mid.resolve("b").resolve("c"));
            // a FILE sdks/pca-less-c/build nearer than both directories is not a build directory
            Files.createDirectories(cwd.resolve("sdks").resolve("pca-less-c"));
            Files.write(cwd.resolve("sdks").resolve("pca-less-c").resolve("build"), new byte[0]);
            List<Path> envs = new ArrayList<>();
            String env = System.getenv("ATLAS_PCA_LIBLESS");
            if (env == null || env.isEmpty()) env = System.getProperty("atlas.pca.libless", "");
            for (String p : env.split(File.pathSeparator)) if (!p.isEmpty()) envs.add(Paths.get(p));

            System.setProperty("user.dir", cwd.toString());
            List<Path> got = LessNative.candidates();
            assertEquals(envs.size() + 3, got.size(), got.toString());
            assertEquals(envs, got.subList(0, envs.size()));
            assertBuildTail(inner, got);
            // without the nearer one, the outer build directory is found
            Files.delete(inner);
            got = LessNative.candidates();
            assertEquals(envs.size() + 3, got.size(), got.toString());
            assertBuildTail(outer, got);
            // no build directory anywhere above: the environment entries alone
            Files.delete(outer);
            assertEquals(envs, LessNative.candidates());
        } finally {
            if (dir == null) System.clearProperty("user.dir"); else System.setProperty("user.dir", dir);
            try (java.util.stream.Stream<Path> w = Files.walk(root)) {
                w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void availableIffARuntimeAndALibrary() {
        boolean lib = false;
        for (Path p : LessNative.candidates()) lib |= Files.isRegularFile(p);
        if (Runtime.version().feature() >= 22 && lib) assertTrue(LessNative.available(), "a Java 22+ runtime with a candidate library must load LESS");
        if (Runtime.version().feature() < 22) assertFalse(LessNative.available());
        assertEquals(LessNative.available(), Pq.SUITES.containsKey("less-cat1"));
        assertEquals(LessNative.available(), Pq.SUITES.containsKey("hybrid-ed25519-less-cat1"));
        assertEquals(LessNative.available(), Pq.supportedSuites().contains("less-cat1"));
        if (!LessNative.available()) {
            // no FFM runtime (Java < 22) or no libatlas_less: the LESS suites are refused fail-closed as unsupported_suite
            for (String alg : new String[] {"less-cat1", "hybrid-ed25519-less-cat1"}) {
                assertNull(Pq.resolveSigAlg(alg, true), alg);
                assertEquals("unsupported_suite: " + alg, Pq.refusal(alg));
                assertEquals("unsupported_suite: '" + alg + "'", IntentJs.suiteError(alg, true));
            }
        }
    }

    // ---------------------------------------------------------------- the FFM verify on the known answers

    /** The cheapest discriminating pair (one valid, one forged) first, so a mutant dies on two native verifies. */
    @Test
    void lessVerifyOneValidOneForged() throws Exception {
        if (!LessNative.available()) return;
        byte[] pk = key("main", "pq_pk");
        Map<String, Object> valid = vector("less-cat1-valid");
        assertTrue(LessNative.verify(pk, bytes(valid, "message"), bytes(valid, "sig")));
        Map<String, Object> forged = vector("less-cat1-flip-digest");
        assertFalse(LessNative.verify(pk, bytes(forged, "message"), bytes(forged, "sig")));
    }

    @Test
    void lessVerifyKnownAnswers() throws Exception {
        if (!LessNative.available()) return;
        byte[] pk = key("main", "pq_pk"), other = key("other", "pq_pk");
        assertEquals(97484, pk.length);
        Map<String, Object> valid = vector("less-cat1-valid");
        byte[] msg = bytes(valid, "message"), sig = bytes(valid, "sig");
        assertEquals(1313, sig.length);
        assertTrue(LessNative.verify(pk, msg, sig));
        assertTrue(LessNative.verify(pk, msg, sig), "repeatable (arena closed, nothing shared)");
        Map<String, Object> v2 = vector("less-cat1-valid-other-key");
        assertTrue(LessNative.verify(other, bytes(v2, "message"), bytes(v2, "sig")));
        assertFalse(LessNative.verify(pk, bytes(v2, "message"), bytes(v2, "sig")), "wrong key");
        assertFalse(LessNative.verify(other, msg, sig), "wrong key");
        // every forged / malleated vector, through the raw entry point
        for (String n : new String[] {"less-cat1-flip-digest", "less-cat1-flip-salt", "less-cat1-flip-seed", "less-cat1-padding-bit",
            "less-cat1-seed-count-up", "less-cat1-seed-count-max", "less-cat1-wrong-message", "less-cat1-drop-last-seed",
            "less-cat1-seed-padded-zero", "less-cat1-seed-padded-junk", "less-cat1-zero-min", "less-cat1-empty-message-forged",
            "less-cat1-truncated-one", "less-cat1-oversize"}) {
            Map<String, Object> v = vector(n);
            assertFalse(LessNative.verify(pk, bytes(v, "message"), bytes(v, "sig")), n);
        }
        // the message is bound: one flipped byte, a dropped byte, an appended byte
        byte[] m2 = msg.clone();
        m2[0] ^= 1;
        assertFalse(LessNative.verify(pk, m2, sig));
        assertFalse(LessNative.verify(pk, Arrays.copyOf(msg, msg.length - 1), sig));
        assertFalse(LessNative.verify(pk, Arrays.copyOf(msg, msg.length + 1), sig));
        assertFalse(LessNative.verify(pk, new byte[0], sig));
        // the signature is bound (last byte)
        byte[] s2 = sig.clone();
        s2[s2.length - 1] ^= 1;
        assertFalse(LessNative.verify(pk, msg, s2));
        // the key is bound (a flipped byte)
        byte[] pk2 = pk.clone();
        pk2[100] ^= 1;
        assertFalse(LessNative.verify(pk2, msg, sig));
    }

    @Test
    void lessVerifyRefusesEachBadArgumentWithoutThrowing() throws Exception {
        byte[] pk = LessNative.available() ? key("main", "pq_pk") : new byte[97484];
        Map<String, Object> valid = vector("less-cat1-valid");
        byte[] msg = bytes(valid, "message"), sig = bytes(valid, "sig");
        assertFalse(LessNative.verify(null, msg, sig));
        assertFalse(LessNative.verify(pk, null, sig));
        assertFalse(LessNative.verify(pk, msg, null));
        assertFalse(LessNative.verify(null, null, null));
        assertFalse(LessNative.verify(Arrays.copyOf(pk, pk.length - 1), msg, sig));
        assertFalse(LessNative.verify(Arrays.copyOf(pk, pk.length + 1), msg, sig));
        assertFalse(LessNative.verify(new byte[0], msg, sig));
        assertFalse(LessNative.verify(pk, msg, Arrays.copyOf(sig, sig.length + 1)));
        assertFalse(LessNative.verify(pk, msg, Arrays.copyOf(sig, sig.length + 16)));
        assertFalse(LessNative.verify(pk, msg, new byte[0]));
        if (!LessNative.available()) assertFalse(LessNative.verify(pk, msg, sig), "no library: fail closed");
    }

    @Test
    void pqVerifyLessAndHybridThroughEveryEntryPoint() throws Exception {
        if (!LessNative.available()) return;
        byte[] pk = key("main", "pq_pk");
        Map<String, Object> valid = vector("less-cat1-valid");
        byte[] msg = bytes(valid, "message"), sig = bytes(valid, "sig");
        assertTrue(Pq.pqVerify(Pq.Prim.LESS_CAT1, pk, msg, sig));
        assertFalse(Pq.pqVerify(Pq.Prim.LESS_CAT1, pk, Arrays.copyOf(msg, 3), sig));
        assertFalse(Pq.pqVerify(Pq.Prim.LESS_CAT1, key("other", "pq_pk"), msg, sig));
        assertFalse(Pq.pqVerify(Pq.Prim.LESS_CAT1, pk, msg, Arrays.copyOf(sig, sig.length - 1)));
        assertTrue(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(sig)));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(Arrays.copyOf(sig, sig.length - 1))));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(Arrays.copyOf(sig, sig.length + 1))));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(Arrays.copyOf(pk, 10)), msg, b64(sig)));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, null, msg, b64(sig)));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, null));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.LESS_CAT1, b64(pk), msg, b64(sig) + "="));
        // the pure suite's `sig` field is the variable-length LESS signature; the hybrid's is the 64-byte Ed25519 one
        Pq.Suite pure = Pq.SUITES.get("less-cat1"), hyb = Pq.SUITES.get("hybrid-ed25519-less-cat1");
        assertTrue(Pq.sigFieldOk(pure, b64(new byte[1153])));
        assertTrue(Pq.sigFieldOk(pure, b64(new byte[1313])));
        assertTrue(Pq.sigFieldOk(pure, b64(new byte[1329])));
        assertFalse(Pq.sigFieldOk(pure, b64(new byte[1154])));
        assertFalse(Pq.sigFieldOk(pure, b64(new byte[64])));
        assertTrue(Pq.sigFieldOk(hyb, b64(new byte[64])));
        assertFalse(Pq.sigFieldOk(hyb, b64(new byte[1313])));
        // the suite verify (caller-vouched key): pure and hybrid known answers
        String ed = (String) ((Map<?, ?>) ((Map<?, ?>) vectors().get("keys")).get("main")).get("ed_pub");
        assertTrue(Pq.verifyArtifactSignature("less-cat1", ed, b64(pk), msg, b64(sig), null));
        Map<String, Object> h = vector("hybrid-less-valid");
        assertTrue(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(h, "message"), h.get("sig"), h.get("pq_sig")));
        assertFalse(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(h, "message"), h.get("sig"), null));
        assertFalse(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(h, "message"), h.get("sig"), 7L));
        Map<String, Object> badEd = vector("hybrid-less-bad-ed25519");
        assertFalse(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(badEd, "message"), badEd.get("sig"), badEd.get("pq_sig")));
        Map<String, Object> badLess = vector("hybrid-less-bad-less");
        assertFalse(Pq.verifyArtifactSignature("hybrid-ed25519-less-cat1", ed, b64(pk), bytes(badLess, "message"), badLess.get("sig"), badLess.get("pq_sig")));
    }

    // ---------------------------------------------------------------- the PQ seams of Pq.java (ML-DSA, no library needed)

    static AsymmetricCipherKeyPair mldsa() {
        MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
        g.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
        return g.generateKeyPair();
    }

    static byte[] mldsaSign(AsymmetricCipherKeyPair k, byte[] msg) throws Exception {
        MLDSASigner s = new MLDSASigner();
        s.init(true, k.getPrivate());
        s.update(msg, 0, msg.length);
        return s.generateSignature();
    }

    @Test
    void pqVerifyRefusesEachBadArgumentWithoutThrowing() throws Exception {
        AsymmetricCipherKeyPair k = mldsa();
        byte[] pk = ((MLDSAPublicKeyParameters) k.getPublic()).getEncoded();
        byte[] msg = "k042 pq verify".getBytes(StandardCharsets.UTF_8);
        byte[] sig = mldsaSign(k, msg);
        assertTrue(Pq.pqVerify(Pq.Prim.ML_DSA_65, pk, msg, sig));
        assertTrue(Pq.mlDsa65Verify(pk, msg, sig));
        assertTrue(Pq.pqVerifyB64u(Pq.Prim.ML_DSA_65, b64(pk), msg, b64(sig)));
        assertFalse(Pq.pqVerify(null, pk, msg, sig));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_65, null, msg, sig));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_65, pk, msg, null));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_65, pk, null, sig));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_65, Arrays.copyOf(pk, pk.length + 1), msg, sig));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_65, Arrays.copyOf(pk, pk.length - 1), msg, sig));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_65, pk, msg, Arrays.copyOf(sig, sig.length + 1)));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_65, pk, msg, Arrays.copyOf(sig, sig.length - 1)));
        assertFalse(Pq.pqVerify(Pq.Prim.ML_DSA_87, pk, msg, sig));
        // the LESS primitive refuses a wrong-length key before (and without) the library
        assertFalse(Pq.pqVerify(Pq.Prim.LESS_CAT1, pk, msg, new byte[1153]));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.ML_DSA_65, null, msg, b64(sig)));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.ML_DSA_65, b64(pk), msg, null));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.ML_DSA_65, b64(pk), msg, b64(Arrays.copyOf(sig, sig.length + 1))));
        assertFalse(Pq.pqVerifyB64u(Pq.Prim.ML_DSA_65, b64(Arrays.copyOf(pk, pk.length + 1)), msg, b64(sig)));
    }

    @Test
    void manifestAndRefusals() {
        List<String> want = new ArrayList<>(Pq.REGISTERED_SUITES);
        want.remove("fn-dsa-512");
        want.remove("fn-dsa-1024");
        if (!LessNative.available()) { want.remove("less-cat1"); want.remove("hybrid-ed25519-less-cat1"); }
        List<String> got = Pq.supportedSuites();
        assertEquals(want, got);
        assertEquals(LessNative.available() ? 12 : 10, got.size());
        assertEquals("ed25519", got.get(0));
        assertThrows(UnsupportedOperationException.class, () -> got.add("x"));
        assertEquals("unknown signature alg 'null'", Pq.refusal(null));
        assertEquals("unknown signature alg '7'", Pq.refusal(7L));
        assertEquals("unknown signature alg 'ed448'", Pq.refusal("ed448"));
        assertEquals("unsupported_suite: less-cat1", Pq.refusal("less-cat1"));
        assertEquals("unsupported_suite: ml-dsa-65", Pq.refusal("ml-dsa-65"));
    }
}
