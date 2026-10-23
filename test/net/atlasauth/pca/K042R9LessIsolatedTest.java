package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * r9 mutation kills for LessNative.java that need a LessNative the process environment cannot reach: a fresh copy of the class
 * (its own static initialiser) is loaded by a child-first loader while ATLAS_PCA_LIBLESS, atlas.pca.libless and user.dir are
 * set to the case under test. The mutation agent rewrites every loader's copy of the class, so these assertions bind the
 * mutants; the in-process env override is the JDK's own String-keyed environment map, reached with Unsafe (no --add-opens).
 */
public class K042R9LessIsolatedTest {
    static { LessNative.available(); } // initialise the real class under the real environment before any case changes it

    public static int closed;
    public static void countClose() { closed++; }

    // ---- environment override ----
    @SuppressWarnings("unchecked")
    static Map<String, String> envMap() {
        try {
            Field uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
            uf.setAccessible(true);
            Object u = uf.get(null);
            Class<?> uc = u.getClass();
            Field f = Class.forName("java.lang.ProcessEnvironment").getDeclaredField("theUnmodifiableEnvironment");
            Object base = uc.getMethod("staticFieldBase", Field.class).invoke(u, f);
            long off = (Long) uc.getMethod("staticFieldOffset", Field.class).invoke(u, f);
            Object unm = uc.getMethod("getObject", Object.class, long.class).invoke(u, base, off);
            Field mf = Class.forName("java.util.Collections$UnmodifiableMap").getDeclaredField("m");
            long moff = (Long) uc.getMethod("objectFieldOffset", Field.class).invoke(u, mf);
            return (Map<String, String>) uc.getMethod("getObject", Object.class, long.class).invoke(u, unm, moff);
        } catch (Throwable t) {
            return null;
        }
    }

    /** Windows only: System.getenv(name) reads ProcessEnvironment.theCaseInsensitiveEnvironment, a separate table. */
    @SuppressWarnings("unchecked")
    static Map<String, String> caseInsensitiveEnv() {
        try {
            Field uf = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
            uf.setAccessible(true);
            Object u = uf.get(null);
            Class<?> uc = u.getClass();
            Field f = Class.forName("java.lang.ProcessEnvironment").getDeclaredField("theCaseInsensitiveEnvironment");
            Object base = uc.getMethod("staticFieldBase", Field.class).invoke(u, f);
            long off = (Long) uc.getMethod("staticFieldOffset", Field.class).invoke(u, f);
            return (Map<String, String>) uc.getMethod("getObject", Object.class, long.class).invoke(u, base, off);
        } catch (Throwable t) {
            return null;   // not Windows: the field does not exist
        }
    }

    static void setEnv(Map<String, String> m, Map<String, String> ci, String v) {
        for (Map<String, String> t : new Map[] {m, ci}) {
            if (t == null) continue;
            if (v == null) t.remove("ATLAS_PCA_LIBLESS"); else t.put("ATLAS_PCA_LIBLESS", v);
        }
    }

    interface Body { void run(Path tmp) throws Exception; }

    /** Runs {@code body} with the three inputs of LessNative.candidates() under control; restores them afterwards. */
    static void withInputs(String env, String prop, Path cwd, Body body) throws Exception {
        Map<String, String> m = envMap(), ci = caseInsensitiveEnv();
        assumeTrue(m != null, "the process environment is not reachable on this runtime");
        String oldEnv = System.getenv("ATLAS_PCA_LIBLESS"), oldProp = System.getProperty("atlas.pca.libless"), oldDir = System.getProperty("user.dir");
        Path tmp = Files.createTempDirectory("k042r9").toAbsolutePath();
        try {
            setEnv(m, ci, env);
            if (prop == null) System.clearProperty("atlas.pca.libless"); else System.setProperty("atlas.pca.libless", prop);
            System.setProperty("user.dir", cwd == null ? tmp.toString() : cwd.toString());
            body.run(tmp);
        } finally {
            setEnv(m, ci, oldEnv);
            if (oldProp == null) System.clearProperty("atlas.pca.libless"); else System.setProperty("atlas.pca.libless", oldProp);
            if (oldDir == null) System.clearProperty("user.dir"); else System.setProperty("user.dir", oldDir);
            try (java.util.stream.Stream<Path> w = Files.walk(tmp)) { w.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }
    }

    // ---- a private copy of LessNative ----
    static final class Iso extends URLClassLoader {
        Iso(URL root) { super(new URL[] {root}, K042R9LessIsolatedTest.class.getClassLoader()); }
        @Override protected Class<?> loadClass(String n, boolean resolve) throws ClassNotFoundException {
            if (!n.equals("net.atlasauth.pca.LessNative") && !n.startsWith("net.atlasauth.pca.LessNative$")) return super.loadClass(n, resolve);
            synchronized (getClassLoadingLock(n)) {
                Class<?> c = findLoadedClass(n);
                if (c == null) c = findClass(n);
                if (resolve) resolveClass(c);
                return c;
            }
        }
    }
    static Class<?> fresh() throws Exception {
        URL root = LessNative.class.getProtectionDomain().getCodeSource().getLocation();
        return new Iso(root).loadClass("net.atlasauth.pca.LessNative");
    }
    static Object call(Class<?> c, String name, Class<?>[] types, Object... args) throws Exception {
        Method m = c.getDeclaredMethod(name, types);
        m.setAccessible(true);
        return m.invoke(null, args);
    }

    static Path library() {
        for (Path p : LessNative.candidates()) if (Files.isRegularFile(p)) return p;
        return null;
    }

    // ---- candidates(): environment, property fallback, upward search ----
    @Test void environmentThenPropertyThenBuildDirectory() throws Exception {
        String a = new File("one.so").getAbsolutePath(), b = new File("two.so").getAbsolutePath();
        String sep = File.pathSeparator;
        withInputs(null, a + sep + sep + b, null, tmp -> assertEquals(List.of(Paths.get(a), Paths.get(b)), LessNative.candidates(), "unset: the property"));
        withInputs("", a, null, tmp -> assertEquals(List.of(Paths.get(a)), LessNative.candidates(), "empty: the property"));
        withInputs(b, a, null, tmp -> assertEquals(List.of(Paths.get(b)), LessNative.candidates(), "set: the variable wins"));
        withInputs(null, null, null, tmp -> assertEquals(List.of(), LessNative.candidates(), "nothing configured, no build directory above"));
        withInputs("", "", null, tmp -> assertEquals(List.of(), LessNative.candidates(), "both empty"));
        withInputs(sep, null, null, tmp -> assertEquals(List.of(), LessNative.candidates(), "separators only"));
    }

    @Test void aRelativeUserDirIsMadeAbsoluteBeforeTheUpwardSearch() throws Exception {
        Path here = Paths.get("").toAbsolutePath();
        Path root = Files.createTempDirectory(here, "k042r9rel");
        try {
            Path build = Files.createDirectories(root.resolve("sdks").resolve("pca-less-c").resolve("build"));
            Files.createDirectories(root.resolve("a").resolve("b"));
            Path rel = here.relativize(root.resolve("a").resolve("b"));
            withInputs(null, null, rel, tmp -> {
                List<Path> got = LessNative.candidates();
                assertEquals(List.of(build.resolve("libatlas_less.so"), build.resolve("libatlas_less.dylib"), build.resolve("atlas_less.dll")), got);
                assertTrue(got.get(0).isAbsolute());
            });
        } finally {
            try (java.util.stream.Stream<Path> w = Files.walk(root)) { w.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }
    }

    // ---- the load ----
    @Test void availableOnlyWithAReadableLibrary() throws Exception {
        Path lib = library();
        withInputs(null, null, null, tmp -> {
            Class<?> c = fresh();
            assertEquals(false, call(c, "available", new Class<?>[0]), "no candidate: LESS is unavailable");
            byte[] pk = new byte[LessNative.PUBLIC_KEY_BYTES], sig = new byte[LessNative.SIGNATURE_MIN_BYTES];
            assertEquals(false, call(c, "verify", new Class<?>[] {byte[].class, byte[].class, byte[].class}, pk, new byte[4], sig), "unavailable: refuse");
        });
        assumeTrue(lib != null && Runtime.version().feature() >= 22, "no library / no FFM here");
        withInputs(lib.toString(), null, null, tmp -> assertEquals(true, call(fresh(), "available", new Class<?>[0])));
        withInputs(null, lib.toString(), null, tmp -> assertEquals(true, call(fresh(), "available", new Class<?>[0])));
        withInputs(tmp0(lib), null, null, tmp -> assertEquals(false, call(fresh(), "available", new Class<?>[0]), "a path that is not a library"));
    }
    private static String tmp0(Path lib) { return lib.resolveSibling("no-such-library.so").toString(); }

    // ---- verify(): failures inside the native call refuse, and the arena is always closed ----
    @Test void anInternalFailureRefusesAndTheArenaIsClosed() throws Exception {
        Path lib = library();
        assumeTrue(lib != null && Runtime.version().feature() >= 22, "no library / no FFM here");
        withInputs(lib.toString(), null, null, tmp -> {
            Class<?> c = fresh();
            Field ff = c.getDeclaredField("FFM");
            ff.setAccessible(true);
            Object ffm = ff.get(null);
            assertNotNull(ffm);
            byte[] pk = new byte[LessNative.PUBLIC_KEY_BYTES], sig = new byte[LessNative.SIGNATURE_MIN_BYTES], msg = {1, 2, 3};
            Class<?>[] t = {byte[].class, byte[].class, byte[].class};
            assertEquals(false, call(c, "verify", t, pk, msg, sig), "a zero key does not verify");
            Field close = ffm.getClass().getDeclaredField("arenaClose"), alloc = ffm.getClass().getDeclaredField("arenaAllocate");
            close.setAccessible(true);
            alloc.setAccessible(true);
            Object realClose = close.get(ffm), realAlloc = alloc.get(ffm);
            // the arena allocation throws: the call refuses (it must not answer true) and still closes the arena
            close.set(ffm, K042R9LessIsolatedTest.class.getMethod("countClose"));
            alloc.set(ffm, String.class.getMethod("length"));
            closed = 0;
            assertEquals(false, call(c, "verify", t, pk, msg, sig), "an internal failure is a refusal");
            assertEquals(1, closed, "the arena is closed on the failure path");
            alloc.set(ffm, realAlloc);
            closed = 0;
            assertEquals(false, call(c, "verify", t, pk, msg, sig));
            assertEquals(1, closed, "the arena is closed on the normal path");
            close.set(ffm, realClose);
        });
    }
}
