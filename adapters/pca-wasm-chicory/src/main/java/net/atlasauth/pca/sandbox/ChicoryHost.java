package net.atlasauth.pca.sandbox;

import net.atlasauth.pca.Json;

import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.HostFunction;
import com.dylibso.chicory.runtime.ImportValues;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.WasmModule;
import com.dylibso.chicory.wasm.types.ExternalType;
import com.dylibso.chicory.wasm.types.FunctionType;
import com.dylibso.chicory.wasm.types.MemoryLimits;
import com.dylibso.chicory.wasm.types.ValType;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Core-module WebAssembly host on Chicory (pure Java, interpreter machine). The tool imports only
 * {@code pca:act.{invoke,handle_count,handle_verb}}; no WASI is linked, so it has no filesystem, network, clock, random or
 * environment. Limits, none optional: an instruction budget ({@code fuel}, required, counted by Chicory's per-instruction
 * {@code ExecutionListener}), a wall-clock deadline (the same listener checks it, and the run thread is interrupted as a second
 * stop), the declared-memory checks of the reference (one memory, a declared maximum, non-shared 32-bit, within the page cap) and
 * Chicory's own maximum-pages enforcement on {@code memory.grow}.
 *
 * <p>Reasons are the reference's: module_size, malformed_module, memory_limits, ambient_import:module.name, no_entry,
 * trap:RuntimeError, trap:LinkError, plus bad_fuel, fuel_exhausted, timeout.
 *
 * <p>Known differences: the listener API is marked experimental upstream (the pom pins 1.7.5); a {@code memory.grow} past the
 * declared maximum returns -1 to the guest (WebAssembly semantics) instead of trapping; an executor that blocks is not stopped by
 * the deadline (only guest code is).
 */
public final class ChicoryHost {
    private ChicoryHost() {}

    /** Run limits. {@code fuel} has no default: a budget is a decision. */
    public static final class Options {
        public final long fuel;
        public long timeoutMs = 5000;
        public int maxModuleBytes = 1 << 20;
        public int maxMemoryPages = 256;
        public int maxResultBytes = 1 << 20;

        public Options(long fuel) { this.fuel = fuel; }
    }

    private static final class FuelExhausted extends RuntimeException {
        FuelExhausted() { super("fuel_exhausted", null, false, false); }
    }

    private static final class DeadlineExceeded extends RuntimeException {
        DeadlineExceeded() { super("timeout", null, false, false); }
    }

    /** {count, min, max(-1 = none), shared} of the first memory; null = no memory section; throws on an unparseable module. */
    static long[] memoryLimits(byte[] b) {
        if (b.length < 8 || b[0] != 0 || b[1] != 0x61 || b[2] != 0x73 || b[3] != 0x6d) throw new IllegalArgumentException("bad magic");
        int[] o = {8};
        while (o[0] < b.length) {
            int id = b[o[0]++] & 0xff;
            long size = leb(b, o);
            long end = o[0] + size;
            if (end > b.length) throw new IllegalArgumentException("section overruns");
            if (id == 5) {
                long count = leb(b, o);
                if (count == 0) return null;
                if (o[0] >= b.length) throw new IllegalArgumentException("eof");
                int flag = b[o[0]++] & 0xff;
                if (flag > 3) return new long[] {count, Long.MAX_VALUE, -1, 1}; // memory64 and anything newer: refused
                long min = leb(b, o);
                long max = (flag & 1) != 0 ? leb(b, o) : -1;
                return new long[] {count, min, max, (flag & 2) != 0 ? 1 : 0};
            }
            o[0] = (int) end;
        }
        return null;
    }

    private static long leb(byte[] b, int[] o) {
        long r = 0;
        for (int shift = 0; shift < 35; shift += 7) {
            if (o[0] >= b.length) throw new IllegalArgumentException("eof");
            int x = b[o[0]++] & 0xff;
            r += (long) (x & 0x7f) << shift;
            if ((x & 0x80) == 0) return r;
        }
        throw new IllegalArgumentException("leb");
    }

    private static boolean chain(Throwable t, Class<? extends Throwable> c) {
        for (int i = 0; t != null && i < 16; i++, t = t.getCause()) if (c.isInstance(t)) return true;
        return false;
    }

    /** Run {@code bytes} (a core module) and call its export {@code entry} over {@code table}. */
    public static WasmSubprocess.Result run(Handles.HandleTable table, byte[] bytes, String entry, Options o) {
        if (o.fuel < 1) return WasmSubprocess.Result.fail("bad_fuel");
        if (o.maxMemoryPages < 1 || o.timeoutMs < 1) return WasmSubprocess.Result.fail("bad_limits");
        if (bytes.length == 0 || bytes.length > o.maxModuleBytes) return WasmSubprocess.Result.fail("module_size");
        try {
            long[] mem = memoryLimits(bytes);
            if (mem != null && (mem[0] > 1 || mem[3] == 1 || mem[2] < 0 || mem[1] > o.maxMemoryPages || mem[2] > o.maxMemoryPages)) return WasmSubprocess.Result.fail("memory_limits");
        } catch (RuntimeException e) {
            return WasmSubprocess.Result.fail("malformed_module");
        }
        WasmModule module;
        try {
            module = Parser.parse(bytes);
        } catch (RuntimeException e) {
            return WasmSubprocess.Result.fail("malformed_module");
        }
        var imports = module.importSection();
        for (int i = 0; imports != null && i < imports.importCount(); i++) {
            var im = imports.getImport(i);
            boolean allowed = im.module().equals(Host.IMPORT_MODULE) && im.importType() == ExternalType.FUNCTION && Host.ALLOWED_IMPORTS.contains(im.name());
            if (!allowed) return WasmSubprocess.Result.fail("ambient_import:" + im.module() + "." + im.name());
        }

        long deadline = System.nanoTime() + o.timeoutMs * 1_000_000L;
        long[] fuel = {o.fuel};
        int[] tick = {0};
        FunctionType i3 = FunctionType.of(List.of(ValType.I32, ValType.I32, ValType.I32), List.of(ValType.I32));
        HostFunction count = new HostFunction(Host.IMPORT_MODULE, "handle_count", FunctionType.of(List.of(), List.of(ValType.I32)),
                (in, a) -> new long[] {table.size()});
        HostFunction verb = new HostFunction(Host.IMPORT_MODULE, "handle_verb", i3, (in, a) -> {
            String v = table.verbOf((int) a[0]);
            if (v == null) return code("unknown_handle");
            Memory m = memory(in);
            long p = a[1] & 0xFFFFFFFFL, l = a[2] & 0xFFFFFFFFL;
            if (m == null || p + l > (long) m.pages() * 65536L) return code("bad_memory");
            byte[] enc = Json.utf8(v);
            if (enc.length > l) return code("out_too_small");
            m.write((int) p, enc);
            return new long[] {enc.length};
        });
        HostFunction invoke = new HostFunction(Host.IMPORT_MODULE, "invoke", i3, (in, a) -> {
            // validate the guest's output window before spending the use
            Memory m = memory(in);
            long p = a[1] & 0xFFFFFFFFL, l = a[2] & 0xFFFFFFFFL;
            if (m == null || p + l > (long) m.pages() * 65536L) return code("bad_memory");
            Handles.UseResult r = table.use((int) a[0]);
            if (!r.ok) return code(r.reason);
            if (r.result.length > o.maxResultBytes || r.result.length > l) return code("out_too_small");
            m.write((int) p, r.result);
            return new long[] {r.result.length};
        });

        AtomicReference<WasmSubprocess.Result> out = new AtomicReference<>();
        Thread t = new Thread(() -> {
            boolean instantiated = false;
            try {
                Instance instance = Instance.builder(module)
                        .withImportValues(ImportValues.builder().addFunction(count, verb, invoke).build())
                        .withMemoryLimits(mem(module, o.maxMemoryPages))
                        .withUnsafeExecutionListener((ins, stack) -> {
                            if (--fuel[0] < 0) throw new FuelExhausted();
                            if ((++tick[0] & 255) == 0 && System.nanoTime() > deadline) throw new DeadlineExceeded();
                        })
                        .build();
                instantiated = true;
                ExportFunction fn;
                try {
                    fn = instance.exports().function(entry);
                } catch (RuntimeException e) {
                    fn = null;
                }
                if (fn == null) {
                    out.set(WasmSubprocess.Result.fail("no_entry"));
                    return;
                }
                long[] r = fn.apply();
                out.set(WasmSubprocess.Result.ok(r != null && r.length > 0 ? (int) r[0] : 0));
            } catch (Throwable e) {
                if (chain(e, FuelExhausted.class)) out.set(WasmSubprocess.Result.fail("fuel_exhausted"));
                else if (chain(e, DeadlineExceeded.class) || chain(e, com.dylibso.chicory.runtime.ChicoryInterruptedException.class)) out.set(WasmSubprocess.Result.fail("timeout"));
                else if (!instantiated) out.set(WasmSubprocess.Result.fail("trap:LinkError"));
                else out.set(WasmSubprocess.Result.fail("trap:RuntimeError"));
            }
        }, "pca-wasm-chicory");
        t.setDaemon(true);
        t.start();
        try {
            t.join(o.timeoutMs + 2000);
            if (t.isAlive()) {
                // the listener normally stops the guest first; this is the second stop
                t.interrupt();
                t.join(1000);
                if (t.isAlive()) return WasmSubprocess.Result.fail("timeout");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            t.interrupt();
            return WasmSubprocess.Result.fail("timeout");
        }
        WasmSubprocess.Result r = out.get();
        return r == null ? WasmSubprocess.Result.fail("trap:RuntimeError") : r;
    }

    private static MemoryLimits mem(WasmModule module, int cap) {
        var sec = module.memorySection();
        if (sec.isEmpty() || sec.get().memoryCount() == 0) return null;
        MemoryLimits d = sec.get().getMemory(0).limits();
        // declared maximum already checked <= cap; clamp anyway so the engine's own limit is the cap
        return new MemoryLimits(d.initialPages(), Math.min(d.maximumPages(), cap));
    }

    private static Memory memory(Instance in) {
        try {
            return in.exports().memory("memory");
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static long[] code(String reason) {
        return new long[] {Handles.USE_ERR.get(reason)};
    }
}
