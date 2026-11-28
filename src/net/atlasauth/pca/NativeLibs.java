package net.atlasauth.pca;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds a native library packaged inside a module's jar, at {@code natives/<os>-<arch>/<System.mapLibraryName(name)>}
 * (os: linux, macos, windows; arch: x64, arm64), and extracts it once to a private temporary directory.
 */
public final class NativeLibs {
    private NativeLibs() {}

    private static final ConcurrentHashMap<String, String> CACHE = new ConcurrentHashMap<>();

    /** The platform directory name, e.g. {@code linux-x64}. */
    public static String platform() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        String o = os.contains("mac") || os.contains("darwin") ? "macos" : os.contains("win") ? "windows" : "linux"; // "darwin" contains "win"
        String a = arch.equals("aarch64") || arch.equals("arm64") ? "arm64" : arch.equals("amd64") || arch.equals("x86_64") ? "x64" : arch;
        return o + "-" + a;
    }

    /** The first non-empty explicit override (system property, environment variable), else the packaged library, else null (system lookup). */
    public static String resolve(Class<?> owner, String name, String... overrides) {
        for (String o : overrides) if (o != null && !o.isEmpty()) return o;
        return extract(owner, name);
    }

    /** Absolute path of the extracted library packaged beside {@code owner}, or null when this jar does not carry it for this platform. */
    public static String extract(Class<?> owner, String name) {
        String file = System.mapLibraryName(name);
        String res = "/natives/" + platform() + "/" + file;
        String hit = CACHE.get(res);
        if (hit != null) return hit;
        try (InputStream in = owner.getResourceAsStream(res)) {
            if (in == null) return null;
            Path dir = Files.createTempDirectory("pca-native");
            Path out = dir.resolve(file);
            Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
            out.toFile().deleteOnExit();
            dir.toFile().deleteOnExit();
            CACHE.put(res, out.toString());
            return out.toString();
        } catch (IOException e) {
            return null; // fall back to the configured or system library
        }
    }
}
