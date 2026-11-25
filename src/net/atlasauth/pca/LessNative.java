package net.atlasauth.pca;

import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * LESS (less-252-45, the {@code less-cat1} / {@code hybrid-ed25519-less-cat1} suites; a NIST additional-signature round-2
 * candidate, not a standard) through the Foreign Function and Memory API to {@code libatlas_less}: the patched LESS reference C
 * of the repository's {@code sdks/pca-less-c}, built as a shared library ({@code sdks/pca-less-c/build.sh}).
 *
 * <p>The API is final in Java 22; this SDK compiles for Java 17, so it is reached reflectively and only on a Java 22+ runtime
 * with 64-bit addresses. The library is found at {@code ATLAS_PCA_LIBLESS} (or the system property {@code atlas.pca.libless};
 * one path, or several separated by the path separator), else in {@code sdks/pca-less-c/build/} of the repository containing
 * the working directory. It counts only if it reports the less-252-45 sizes. Without a runtime, a library or native access,
 * the LESS suites are not registered and fail closed with {@code unsupported_suite}. Run with
 * {@code --enable-native-access=ALL-UNNAMED} to keep the JDK's restricted-method warning quiet. Never throws.
 */
public final class LessNative {
    private LessNative() {}

    public static final int PUBLIC_KEY_BYTES = 97484;
    public static final int SIGNATURE_MIN_BYTES = 1153;
    public static final int SIGNATURE_MAX_BYTES = 1329;
    private static final int SIGNATURE_STEP_BYTES = 16;
    /** The secret key is the 32-byte seed the public key is expanded from; keygen and sign take at least this many seed bytes. */
    public static final int SECRET_KEY_BYTES = 32;
    public static final int SEED_BYTES = 32;

    /** The FFM pieces used per call (null when LESS is unavailable). */
    private static final class Ffm {
        MethodHandle verify, keygen, sign; // keygen / sign are null when the library predates the signing entry points
        Method arenaOfConfined, arenaAllocate, arenaClose, segOfArray, segCopyFrom, segToArray;
        Object byteLayout;
    }

    private static final Ffm FFM = load();

    /** True iff a usable libatlas_less is loaded. */
    public static boolean available() { return FFM != null; }

    /** {@code n} is a signature length the parameter set produces. */
    public static boolean sigLenOk(int n) {
        int below = SIGNATURE_MAX_BYTES - n; // a produced length is MAX - k * STEP, at least MIN
        return n >= SIGNATURE_MIN_BYTES && below >= 0 && below % SIGNATURE_STEP_BYTES == 0;
    }

    /** Candidate library paths, in order. */
    static List<Path> candidates() {
        List<Path> out = new ArrayList<>();
        String env = System.getenv("ATLAS_PCA_LIBLESS");
        if (env == null || env.isEmpty()) env = System.getProperty("atlas.pca.libless", "");
        for (String p : env.split(java.io.File.pathSeparator)) if (!p.isEmpty()) out.add(Paths.get(p));
        String packaged = NativeLibs.extract(LessNative.class, "atlas_less"); // after an explicit override, before the repo build directory
        if (packaged != null) out.add(Paths.get(packaged));
        for (Path d = Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath(); d != null; d = d.getParent()) {
            Path build = d.resolve("sdks").resolve("pca-less-c").resolve("build");
            if (!Files.isDirectory(build)) continue;
            for (String n : new String[] {"libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll"}) out.add(build.resolve(n));
            break;
        }
        return out;
    }

    private static Ffm load() {
        try {
            if (Runtime.version().feature() < 22) return null;
            Class<?> linkerC = Class.forName("java.lang.foreign.Linker");
            Class<?> arenaC = Class.forName("java.lang.foreign.Arena");
            Class<?> lookupC = Class.forName("java.lang.foreign.SymbolLookup");
            Class<?> layoutC = Class.forName("java.lang.foreign.MemoryLayout");
            Class<?> valueC = Class.forName("java.lang.foreign.ValueLayout");
            Class<?> descC = Class.forName("java.lang.foreign.FunctionDescriptor");
            Class<?> segC = Class.forName("java.lang.foreign.MemorySegment");
            Class<?> optC = Class.forName("java.lang.foreign.Linker$Option");
            Object address = valueC.getField("ADDRESS").get(null);
            if ((long) layoutC.getMethod("byteSize").invoke(address) != 8) return null; // size_t is bound as a 64-bit long
            Object jLong = valueC.getField("JAVA_LONG").get(null);
            Object jInt = valueC.getField("JAVA_INT").get(null);
            Object linker = linkerC.getMethod("nativeLinker").invoke(null);
            Object global = arenaC.getMethod("global").invoke(null);
            Method descOf = descC.getMethod("of", layoutC, layoutC.arrayType());
            Object sizeDesc = descOf.invoke(null, jLong, Array.newInstance(layoutC, 0));
            Object[] args = (Object[]) Array.newInstance(layoutC, 6);
            for (int i = 0; i < 6; i++) args[i] = i % 2 == 0 ? address : jLong;
            Object verifyDesc = descOf.invoke(null, jInt, args); // (ptr, len, ptr, len, ptr, len) -> int: verify and keygen share the shape
            Object[] signArgs = (Object[]) Array.newInstance(layoutC, 9);
            for (int i = 0; i < 9; i++) signArgs[i] = i % 2 == 0 ? address : jLong;
            Object signDesc = descOf.invoke(null, jInt, signArgs);
            Method downcall = linkerC.getMethod("downcallHandle", segC, descC, optC.arrayType());
            Method find = lookupC.getMethod("find", String.class);
            for (Path path : candidates()) {
                if (!Files.isRegularFile(path)) continue;
                try {
                    Object lookup = lookupC.getMethod("libraryLookup", Path.class, arenaC).invoke(null, path, global);
                    MethodHandle[] sizes = new MethodHandle[3];
                    String[] names = {"atlas_less_cat1_public_key_bytes", "atlas_less_cat1_signature_min_bytes", "atlas_less_cat1_signature_max_bytes"};
                    long[] want = {PUBLIC_KEY_BYTES, SIGNATURE_MIN_BYTES, SIGNATURE_MAX_BYTES};
                    boolean ok = true;
                    for (int i = 0; i < 3 && ok; i++) {
                        Optional<?> sym = (Optional<?>) find.invoke(lookup, names[i]);
                        if (sym.isEmpty()) { ok = false; break; }
                        sizes[i] = (MethodHandle) downcall.invoke(linker, sym.get(), sizeDesc, Array.newInstance(optC, 0));
                        ok = (long) sizes[i].invokeWithArguments() == want[i];
                    }
                    Optional<?> v = (Optional<?>) find.invoke(lookup, "atlas_less_cat1_verify");
                    if (!ok || v.isEmpty()) continue;
                    Ffm f = new Ffm();
                    f.verify = (MethodHandle) downcall.invoke(linker, v.get(), verifyDesc, Array.newInstance(optC, 0));
                    Optional<?> kg = (Optional<?>) find.invoke(lookup, "atlas_less_cat1_keygen");
                    Optional<?> sg = (Optional<?>) find.invoke(lookup, "atlas_less_cat1_sign");
                    if (kg.isPresent() && sg.isPresent()) {
                        f.keygen = (MethodHandle) downcall.invoke(linker, kg.get(), verifyDesc, Array.newInstance(optC, 0));
                        f.sign = (MethodHandle) downcall.invoke(linker, sg.get(), signDesc, Array.newInstance(optC, 0));
                    }
                    f.byteLayout = valueC.getField("JAVA_BYTE").get(null);
                    f.segToArray = segC.getMethod("toArray", Class.forName("java.lang.foreign.ValueLayout$OfByte"));
                    f.arenaOfConfined = arenaC.getMethod("ofConfined");
                    f.arenaAllocate = arenaC.getMethod("allocate", long.class);
                    f.arenaClose = arenaC.getMethod("close");
                    f.segOfArray = segC.getMethod("ofArray", byte[].class);
                    f.segCopyFrom = segC.getMethod("copyFrom", segC);
                    return f;
                } catch (ReflectiveOperationException | RuntimeException e) {
                    // not this library (or no native access): try the next one
                }
            }
        } catch (Throwable t) {
            // no FFM runtime: LESS is unsupported
        }
        return null;
    }

    /** The detached signature opens under {@code pk} and yields exactly {@code msg}. Never throws. */
    public static boolean verify(byte[] pk, byte[] msg, byte[] sig) {
        if (FFM == null || pk == null || msg == null || sig == null || pk.length != PUBLIC_KEY_BYTES || !sigLenOk(sig.length)) return false;
        try {
            Object arena = FFM.arenaOfConfined.invoke(null);
            try {
                byte[][] in = {pk, msg.length == 0 ? new byte[1] : msg, sig};
                Object[] segs = new Object[in.length];
                for (int i = 0; i < 3; i++) {
                    segs[i] = FFM.arenaAllocate.invoke(arena, (long) in[i].length);
                    FFM.segCopyFrom.invoke(segs[i], FFM.segOfArray.invoke(null, (Object) in[i]));
                }
                Object rc = FFM.verify.invokeWithArguments(segs[0], (long) pk.length, segs[1], (long) msg.length, segs[2], (long) sig.length);
                return (int) rc == 1;
            } finally {
                FFM.arenaClose.invoke(arena);
            }
        } catch (Throwable t) {
            return false;
        }
    }

    /** True iff the loaded library carries the keygen and sign entry points. */
    public static boolean canSign() { return FFM != null && FFM.keygen != null && FFM.sign != null; }

    private static Object segOf(Object arena, byte[] in) throws ReflectiveOperationException {
        Object seg = FFM.arenaAllocate.invoke(arena, (long) in.length);
        FFM.segCopyFrom.invoke(seg, FFM.segOfArray.invoke(null, (Object) in));
        return seg;
    }

    private static byte[] bytesOf(Object seg, int n) throws ReflectiveOperationException {
        byte[] all = (byte[]) FFM.segToArray.invoke(seg, FFM.byteLayout);
        return java.util.Arrays.copyOf(all, n);
    }

    /**
     * Deterministic key pair from a seed of at least {@link #SEED_BYTES}: {@code {publicKey, secretKey}}. Throws
     * IllegalStateException when the library (or its signing entry points) is unavailable or the call fails.
     */
    public static byte[][] keygen(byte[] seed) {
        if (!canSign()) throw new IllegalStateException("LESS signing is unavailable: libatlas_less with the keygen entry point is not loaded");
        if (seed == null || seed.length < SEED_BYTES) throw new IllegalArgumentException("a LESS seed is at least " + SEED_BYTES + " bytes");
        try {
            Object arena = FFM.arenaOfConfined.invoke(null);
            try {
                Object pk = FFM.arenaAllocate.invoke(arena, (long) PUBLIC_KEY_BYTES);
                Object sk = FFM.arenaAllocate.invoke(arena, (long) SECRET_KEY_BYTES);
                Object sd = segOf(arena, seed);
                Object rc = FFM.keygen.invokeWithArguments(pk, (long) PUBLIC_KEY_BYTES, sk, (long) SECRET_KEY_BYTES, sd, (long) seed.length);
                if ((int) rc != 1) throw new IllegalStateException("LESS keygen failed");
                return new byte[][] {bytesOf(pk, PUBLIC_KEY_BYTES), bytesOf(sk, SECRET_KEY_BYTES)};
            } finally {
                FFM.arenaClose.invoke(arena);
            }
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("LESS keygen failed", t);
        }
    }

    /** Detached signature (1153..1329 bytes) of {@code msg} under {@code sk}, the signing RNG seeded from {@code seed} (at least 32 bytes). */
    public static byte[] sign(byte[] sk, byte[] msg, byte[] seed) {
        if (!canSign()) throw new IllegalStateException("LESS signing is unavailable: libatlas_less with the sign entry point is not loaded");
        if (sk == null || sk.length != SECRET_KEY_BYTES) throw new IllegalArgumentException("a LESS secret key is " + SECRET_KEY_BYTES + " bytes");
        if (msg == null) throw new IllegalArgumentException("message must be a byte array");
        if (seed == null || seed.length < SEED_BYTES) throw new IllegalArgumentException("a LESS seed is at least " + SEED_BYTES + " bytes");
        try {
            Object arena = FFM.arenaOfConfined.invoke(null);
            try {
                Object skS = segOf(arena, sk);
                Object msS = segOf(arena, msg.length == 0 ? new byte[1] : msg);
                Object sdS = segOf(arena, seed);
                Object sigS = FFM.arenaAllocate.invoke(arena, (long) SIGNATURE_MAX_BYTES);
                Object lenS = FFM.arenaAllocate.invoke(arena, 8L);
                Object rc = FFM.sign.invokeWithArguments(skS, (long) sk.length, msS, (long) msg.length, sdS, (long) seed.length,
                    sigS, (long) SIGNATURE_MAX_BYTES, lenS);
                if ((int) rc != 1) throw new IllegalStateException("LESS sign failed");
                byte[] lb = bytesOf(lenS, 8);
                long n = java.nio.ByteBuffer.wrap(lb).order(java.nio.ByteOrder.nativeOrder()).getLong();
                if (n < SIGNATURE_MIN_BYTES || n > SIGNATURE_MAX_BYTES || !sigLenOk((int) n)) throw new IllegalStateException("LESS sign returned a wrong-length signature");
                return bytesOf(sigS, (int) n);
            } finally {
                FFM.arenaClose.invoke(arena);
            }
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("LESS sign failed", t);
        }
    }
}
