package net.atlasauth.pca.sandbox;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import net.atlasauth.pca.Json;

/**
 * WebAssembly hosts run as a subprocess of the reference {@code pca-wasmtime-host} binary: a component (canonical ABI) or, in
 * {@code core} mode, a core module. The binary does the work (instruction fuel, a wall-clock epoch deadline, a hard memory cap, the
 * import allow-list with no WASI); this class pins it, spawns it with an empty environment and no shell, and serves its handle
 * requests from a {@link Handles.HandleTable} over JSON lines.
 *
 * <p>Trust in the binary: the path and the SHA-256 come from configuration only. A missing binary, a missing pin or a different hash
 * is refused before anything runs. The verified bytes are copied into a private temp directory and that copy is executed, so there
 * is no window between the hash and the exec.
 *
 * <p>Every method returns {@link Result}; reasons are the host's (fuel_exhausted, timeout, memory_limits, ambient_import:...,
 * trap:RuntimeError, ...) plus bad_fuel, host_unpinned, host_missing, host_hash_mismatch, host_unavailable, host_protocol, host_exit.
 */
public final class WasmSubprocess {
    /** Outcome of a run. */
    public static final class Result {
        public final boolean ok;
        public final long value;
        public final String reason;

        private Result(boolean ok, long value, String reason) { this.ok = ok; this.value = value; this.reason = reason; }

        public static Result ok(long v) { return new Result(true, v, null); }

        public static Result fail(String r) { return new Result(false, 0, r); }

        @Override public String toString() { return ok ? "ok:" + value : "fail:" + reason; }
    }

    private static final long MAX_FUEL = 9007199254740991L;

    private final Path binary;
    private final String expectedSha256;

    /** @param binary the reference host (from configuration only); @param expectedSha256 its SHA-256, 64 hex chars */
    public WasmSubprocess(Path binary, String expectedSha256) {
        this.binary = binary;
        this.expectedSha256 = expectedSha256 == null ? "" : expectedSha256.toLowerCase(java.util.Locale.ROOT);
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    /** Run a component (binary or WAT text). {@code fuel} has no default: a budget is a decision. */
    public Result runComponent(Handles.HandleTable table, byte[] component, long fuel, long timeoutMs, int maxResultBytes) {
        if (fuel < 1 || fuel > MAX_FUEL) return Result.fail("bad_fuel");
        List<String> args = new ArrayList<>();
        args.add("@FILE@");
        args.add(Long.toString(fuel));
        return run(table, component, args, timeoutMs, maxResultBytes);
    }

    /** Run a core module's export {@code entry} under fuel, a wall-clock deadline and a cap of {@code maxPages} 64 KiB pages. */
    public Result runCore(Handles.HandleTable table, byte[] module, long fuel, String entry, long maxPages, long timeoutMs, int maxModuleBytes, int maxResultBytes) {
        if (fuel < 1 || fuel > MAX_FUEL) return Result.fail("bad_fuel");
        if (maxPages < 1 || maxPages > 65536 || timeoutMs < 1) return Result.fail("bad_limits");
        if (module.length == 0 || module.length > maxModuleBytes || module.length > (1 << 20)) return Result.fail("module_size");
        List<String> args = new ArrayList<>(List.of("core", "@FILE@", Long.toString(fuel), Long.toString(maxPages), Long.toString(timeoutMs), entry));
        // the host enforces its own deadline; this parent's kill timer is a little longer so the host's reason wins
        return run(table, module, args, timeoutMs + 1000, maxResultBytes);
    }

    private Result run(Handles.HandleTable table, byte[] payload, List<String> args, long timeoutMs, int maxResult) {
        if (expectedSha256.length() != 64 || !expectedSha256.matches("[0-9a-f]{64}")) return Result.fail("host_unpinned");
        byte[] bin;
        try {
            bin = Files.readAllBytes(binary);
        } catch (IOException | RuntimeException e) {
            return Result.fail("host_missing");
        }
        try {
            if (!MessageDigest.isEqual(hex(MessageDigest.getInstance("SHA-256").digest(bin)).getBytes(StandardCharsets.US_ASCII), expectedSha256.getBytes(StandardCharsets.US_ASCII))) {
                return Result.fail("host_hash_mismatch");
            }
        } catch (java.security.NoSuchAlgorithmException e) {
            return Result.fail("host_unavailable");
        }
        Path dir = null;
        Process p = null;
        try {
            dir = net.atlasauth.pca.PrivateFiles.createTempDirectory("pca-comp-");
            Path exe = dir.resolve("host");
            net.atlasauth.pca.PrivateFiles.write(exe, bin);
            if (!exe.toFile().setExecutable(true, true)) return Result.fail("host_unavailable");
            Path file = dir.resolve("tool.wasm");
            net.atlasauth.pca.PrivateFiles.write(file, payload);
            List<String> cmd = new ArrayList<>();
            cmd.add(exe.toString());
            for (String a : args) cmd.add(a.equals("@FILE@") ? file.toString() : a);
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().clear();
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            p = pb.start();
            return serve(table, p, timeoutMs, maxResult);
        } catch (IOException | RuntimeException e) {
            return Result.fail("host_unavailable");
        } finally {
            if (p != null) p.destroyForcibly();
            if (dir != null) {
                try (var w = Files.walk(dir)) {
                    w.sorted(Comparator.reverseOrder()).forEach(x -> x.toFile().delete());
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    private static final String EOF = "\0eof";

    private static Result serve(Handles.HandleTable table, Process p, long timeoutMs, int maxResult) throws IOException {
        BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = r.readLine()) != null) lines.add(l);
            } catch (IOException ignored) {
                // closed
            }
            lines.add(EOF);
        });
        reader.setDaemon(true);
        reader.start();
        OutputStream in = p.getOutputStream();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (true) {
            String line;
            try {
                line = lines.poll(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Result.fail("host_unavailable");
            }
            if (line == null) return Result.fail("timeout");
            if (line.equals(EOF)) return Result.fail("host_exit");
            Object parsed;
            try {
                parsed = Json.parse(line);
            } catch (IllegalArgumentException e) {
                return Result.fail("host_protocol");
            }
            if (!(parsed instanceof Map)) return Result.fail("host_protocol");
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) parsed;
            if (m.get("fail") instanceof String f) return Result.fail(f);
            if (Json.isSafeInt(m.get("done"))) return Result.ok(Json.asLong(m.get("done")));
            long h = Json.isSafeInt(m.get("h")) ? Json.asLong(m.get("h")) : 0;
            String reply;
            Object op = m.get("op");
            if ("count".equals(op)) {
                reply = "{\"n\":" + table.size() + "}";
            } else if ("verb".equals(op)) {
                String v = table.verbOf(h);
                reply = v == null ? "{\"err\":-1}" : "{\"ok\":" + Json.canonicalize(v) + "}";
            } else if ("invoke".equals(op)) {
                Handles.UseResult r = table.use(h);
                if (!r.ok) {
                    Long code = Handles.USE_ERR.get(r.reason);
                    reply = "{\"err\":" + (code == null ? -5 : code) + "}";
                } else if (r.result.length > maxResult) {
                    reply = "{\"err\":-3}";
                } else {
                    StringBuilder b = new StringBuilder("{\"ok\":[");
                    for (int i = 0; i < r.result.length; i++) b.append(i == 0 ? "" : ",").append(r.result[i] & 0xff);
                    reply = b.append("]}").toString();
                }
            } else {
                return Result.fail("host_protocol");
            }
            try {
                // requests are answered strictly one at a time, in order
                in.write(Json.utf8((reply + "\n")));
                in.flush();
            } catch (IOException e) {
                return Result.fail("host_exit");
            }
        }
    }
}
