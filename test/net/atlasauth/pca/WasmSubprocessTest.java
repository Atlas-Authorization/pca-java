package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.sandbox.Handles;
import net.atlasauth.pca.sandbox.ReferenceComponent;
import net.atlasauth.pca.sandbox.ReferenceTool;
import net.atlasauth.pca.sandbox.Receipts;
import net.atlasauth.pca.sandbox.WasmSubprocess;
import org.junit.jupiter.api.Test;

/** The pinned subprocess hosts: pin refusals, the protocol against a fake host, and real runs when a built reference host is named. */
public class WasmSubprocessTest {
    private static String sha(byte[] b) throws Exception {
        StringBuilder s = new StringBuilder();
        for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    private static Handles.HandleTable table() {
        Map<String, Handles.Executor> ex = new LinkedHashMap<>();
        ex.put("fs.read", (v, r, p) -> new byte[] {5, 6});
        var t = new Handles.HandleTable("wasi_no_ambient", new Receipts.ReceiptLog(), ex, null);
        Map<String, Object> params = new LinkedHashMap<>();
        var op = new Authorize.AuthorizedOperation("fs.read", "/x", Pca.hashCanonical(params), "op");
        var res = new Authorize.AuthorizeResult(true, 200, new LinkedHashMap<String, String>(), new ArrayList<String>(), null, op, null, null, new ArrayList<String>());
        t.mint(res, new Authorize.Operation("fs.read", "/x", params), new Handles.MintOptions());
        return t;
    }

    private static WasmSubprocess fake(String body) throws Exception {
        Path dir = Files.createTempDirectory("pca-host-test-");
        Path f = dir.resolve("host.sh");
        byte[] script = ("#!/bin/sh\n" + body + "\n").getBytes(StandardCharsets.UTF_8);
        Files.write(f, script);
        f.toFile().setExecutable(true);
        return new WasmSubprocess(f, sha(script));
    }

    private static WasmSubprocess real() {
        String p = System.getenv("PCA_WASMTIME_HOST_BIN"), h = System.getenv("PCA_WASMTIME_HOST_SHA256");
        if (p == null || h == null) {
            String ci = System.getenv("CI");
            if (ci != null && !ci.isEmpty()) throw new AssertionError("CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256");
        }
        assumeTrue(p != null && h != null, "PCA_WASMTIME_HOST_BIN / PCA_WASMTIME_HOST_SHA256 not set");
        return new WasmSubprocess(Path.of(p), h);
    }

    private static final byte[] X = {'x'};

    private static boolean windows() { return System.getProperty("os.name", "").toLowerCase().contains("win"); }

    /** An existing file the pin checks can read: /bin/sh, or a stand-in on a platform that has none. */
    private static Path sh() throws Exception { return windows() ? Files.createTempFile("pca-host-", ".bin") : Path.of("/bin/sh"); }

    @Test void pinRefusals() throws Exception {
        assertEquals("host_missing", new WasmSubprocess(Path.of("/nonexistent/pca-wasmtime-host"), "a".repeat(64)).runComponent(table(), X, 100, 1000, 1 << 20).reason);
        assertEquals("host_unpinned", new WasmSubprocess(sh(), "").runComponent(table(), X, 100, 1000, 1 << 20).reason);
        assertEquals("host_hash_mismatch", new WasmSubprocess(sh(), "0".repeat(64)).runCore(table(), X, 100, "run", 256, 1000, 1 << 20, 1 << 20).reason);
        assertEquals("bad_fuel", new WasmSubprocess(sh(), "0".repeat(64)).runComponent(table(), X, 0, 1000, 1 << 20).reason);
        assertEquals("module_size", new WasmSubprocess(sh(), "0".repeat(64)).runCore(table(), new byte[0], 10, "run", 256, 1000, 1 << 20, 1 << 20).reason);
    }

    @Test void protocolAgainstFakeHost() throws Exception {
        assumeTrue(!windows(), "the fake host is a POSIX shell script");
        var h = fake("printf '{\"op\":\"count\"}\\n'; read a; printf '{\"op\":\"invoke\",\"h\":1}\\n'; read b; case \"$b\" in *\"[5,6]\"*) printf '{\"done\":5,\"fuel_used\":1}\\n';; *) printf '{\"fail\":\"bad_reply\"}\\n';; esac");
        var t = table();
        var r = h.runComponent(t, X, 1000, 5000, 1 << 20);
        assertTrue(r.ok, r.toString());
        assertEquals(5, r.value);
        // the use is spent: the second run is answered err -2 and the fake reports it
        assertEquals("bad_reply", h.runComponent(t, X, 1000, 5000, 1 << 20).reason);
    }

    @Test void hungGarbageAndExitingHosts() throws Exception {
        assumeTrue(!windows(), "the fake hosts are POSIX shell scripts");
        assertEquals("timeout", fake("read a").runComponent(table(), X, 1000, 300, 1 << 20).reason);
        assertEquals("host_protocol", fake("echo not-json").runComponent(table(), X, 1000, 5000, 1 << 20).reason);
        assertEquals("host_exit", fake("exit 0").runComponent(table(), X, 1000, 5000, 1 << 20).reason);
        assertEquals("fuel_exhausted", fake("echo '{\"fail\":\"fuel_exhausted\"}'").runComponent(table(), X, 1000, 5000, 1 << 20).reason);
    }

    @Test void realHostLimits() {
        var h = real();
        byte[] wat = ReferenceComponent.referenceComponentWat(null).getBytes(StandardCharsets.UTF_8);
        var first = h.runComponent(table(), wat, 1_000_000, 10_000, 1 << 20);
        assertEquals(5, first.value, first.toString());
        Map<String, Object> spin = new LinkedHashMap<>();
        spin.put("spin", Boolean.TRUE);
        assertEquals("fuel_exhausted", h.runComponent(table(), ReferenceComponent.referenceComponentWat(spin).getBytes(StandardCharsets.UTF_8), 10_000, 10_000, 1 << 20).reason);
        Map<String, Object> amb = new LinkedHashMap<>();
        amb.put("extraImport", "wasi:cli/environment@0.2.0");
        assertEquals("ambient_import:wasi:cli/environment@0.2.0", h.runComponent(table(), ReferenceComponent.referenceComponentWat(amb).getBytes(StandardCharsets.UTF_8), 1_000_000, 10_000, 1 << 20).reason);
    }

    @Test void realHostCoreMode() {
        var h = real();
        Map<String, Object> call = new LinkedHashMap<>(Map.of("handle", 1, "ptr", 0, "cap", 16));
        Map<String, Object> spec = new LinkedHashMap<>();
        spec.put("calls", List.of(call));
        spec.put("returns", "byte0");
        var first = h.runCore(table(), ReferenceTool.buildTool(spec), 1_000_000, "run", 256, 5000, 1 << 20, 1 << 20);
        assertEquals(5, first.value, first.toString());
        Map<String, Object> loop = new LinkedHashMap<>();
        loop.put("calls", List.of());
        loop.put("spin", Boolean.TRUE);
        assertEquals("fuel_exhausted", h.runCore(table(), ReferenceTool.buildTool(loop), 10_000, "run", 256, 5000, 1 << 20, 1 << 20).reason);
    }
}
