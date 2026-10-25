package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * LessNative.candidates() with ATLAS_PCA_LIBLESS UNSET and the system-property fallback, which the in-process tests cannot
 * reach when the environment (CI mutation job) provides the library: a child JVM with the variable removed prints the
 * candidates.
 */
public class K042LessNativeEnvTest {
    public static void main(String[] a) {
        for (Path p : LessNative.candidates()) System.out.println(p);
    }

    static List<String> child(String sysprop, String envValue, Path cwd) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path")));
        if (sysprop != null) cmd.add("-Datlas.pca.libless=" + sysprop);
        cmd.add("net.atlasauth.pca.K042LessNativeEnvTest");
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(cwd.toFile()).redirectErrorStream(true);
        pb.environment().remove("ATLAS_PCA_LIBLESS");
        if (envValue != null) pb.environment().put("ATLAS_PCA_LIBLESS", envValue);
        Process pr = pb.start();
        String out = new String(pr.getInputStream().readAllBytes());
        assertEquals(0, pr.waitFor(), out);
        List<String> lines = new ArrayList<>();  // split on \R: the child prints CRLF on Windows
        for (String l : out.split("\\R")) if (!l.isEmpty() && !l.startsWith("NOTE:") && !l.startsWith("WARNING")) lines.add(l);
        return lines;
    }

    @Test
    void systemPropertyFallbackWhenTheEnvironmentIsUnsetOrEmpty() throws Exception {
        Path tmp = Files.createTempDirectory("k042-env").toAbsolutePath();
        try {
            String a = new File(tmp.toFile(), "one.so").getPath(), b = new File(tmp.toFile(), "two.so").getPath();
            assertEquals(List.of(a, b), child(a + File.pathSeparator + File.pathSeparator + b, null, tmp));
            assertEquals(List.of(a), child(a, "", tmp), "an empty variable falls back to the property");
            assertEquals(List.of(), child(null, null, tmp), "nothing set, no build directory above");
            assertEquals(List.of(b), child(a, b, tmp), "the variable wins over the property");
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
