package net.atlasauth.pca.sandbox;

import java.util.Map;
import java.util.function.DoubleSupplier;

/**
 * A WebAssembly host whose only authority is the handles minted into {@link #table} (the reference {@code createSandbox}). The tool is a core
 * module that imports nothing but {@code pca:act.{invoke,handle_count,handle_verb}}; any other import, a memory with no declared maximum, or a
 * shared / 64-bit memory is refused before anything runs. Execution is {@link ChicoryHost} (a fuel budget and a wall-clock deadline, both required
 * decisions here: the JDK has no WebAssembly runtime of its own).
 *
 * <p>The table's runtime class is what the {@code runtimeClaim} PROVES (at most {@code wasi_no_ambient}, {@code egress_default_deny} or
 * {@code os_confined}); without a claim that verifies it is {@code none}: an operator's say-so does not count.
 */
public final class Sandbox {
    /** The options of {@link #createSandbox}. */
    public static final class Options {
        public final Map<String, Handles.Executor> executors;
        /** The instruction budget of every run (required: a budget is a decision). */
        public final long fuel;
        public Receipts.ReceiptLog log;
        public DoubleSupplier now;
        /** A claim and the trust it is judged under ({@link RuntimeClaims#verifiedRuntimeClass}); both null: class {@code none}. */
        public Object runtimeClaim, claimTrust;
        public long timeoutMs = 5000;
        /** Largest tool binary accepted. Default 1 MiB. */
        public int maxModuleBytes = 1 << 20;
        /** Largest linear memory a tool may declare (64 KiB pages). Default 256 (16 MiB). */
        public int maxMemoryPages = 256;
        /** Largest result one handle use may return to the tool. Default 1 MiB. */
        public int maxResultBytes = 1 << 20;

        public Options(Map<String, Handles.Executor> executors, long fuel) { this.executors = executors; this.fuel = fuel; }
    }

    /** The handles this sandbox's tools can use. */
    public final Handles.HandleTable table;
    /** Every receipt the table wrote. */
    public final Receipts.ReceiptLog log;
    private final ChicoryHost.Options limits;

    private Sandbox(Handles.HandleTable table, Receipts.ReceiptLog log, ChicoryHost.Options limits) {
        this.table = table;
        this.log = log;
        this.limits = limits;
    }

    public static Sandbox createSandbox(Options o) {
        Receipts.ReceiptLog log = o.log != null ? o.log
            : o.now != null ? new Receipts.ReceiptLog(() -> Long.valueOf((long) o.now.getAsDouble()), null) : new Receipts.ReceiptLog();
        // a WASM host cannot prove more than wasi_no_ambient, so a stronger claim is capped there
        String proven = o.runtimeClaim != null ? RuntimeClaims.verifiedRuntimeClass(o.runtimeClaim, o.claimTrust) : "none";
        String tableClass = proven.equals("wasi_no_ambient") || proven.equals("egress_default_deny") || proven.equals("os_confined") ? proven : "none";
        ChicoryHost.Options limits = new ChicoryHost.Options(o.fuel);
        limits.timeoutMs = o.timeoutMs;
        limits.maxModuleBytes = o.maxModuleBytes;
        limits.maxMemoryPages = o.maxMemoryPages;
        limits.maxResultBytes = o.maxResultBytes;
        return new Sandbox(new Handles.HandleTable(tableClass, log, o.executors, o.now), log, limits);
    }

    /** Validate the module (size, memory limits, imports) and run its export {@code entry} over the table. Never throws for a bad module: the reason says why. */
    public WasmSubprocess.Result run(byte[] bytes, String entry) { return ChicoryHost.run(table, bytes, entry != null ? entry : "run", limits); }

    public WasmSubprocess.Result run(byte[] bytes) { return run(bytes, "run"); }
}
