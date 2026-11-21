package net.atlasauth.pca.storeconformance;

import net.atlasauth.pca.Json;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.doctor.Js;

/**
 * History recording. The invocation is recorded BEFORE the request leaves the client and the response after it completes. An
 * operation that errors, times out or whose client dies keeps an open-ended interval (ret infinite, outcome unknown): it may or
 * may not have taken effect, at any time after its invocation.
 */
public interface Recorder {
    /** Wall-clock milliseconds with sub-millisecond resolution; comparable across threads (and processes on one host). */
    static double clock() { return Clock.nowMs(); }

    Op invoke(String client, String kind, String key, double lo, double w);

    /** {@code Boolean.TRUE} / {@code FALSE}: the definite answer; {@code null}: the call failed or timed out (stays open-ended). */
    void complete(Op op, Boolean result);

    /** True once this recorder was killed: an invocation made after that was never written, so the call must not be issued (its effect would be unaccounted for). */
    default boolean dead() { return false; }

    /** The shared time base: epoch milliseconds at start plus the monotonic offset since. */
    final class Clock {
        private static final double BASE_MS = System.currentTimeMillis();
        private static final long NANO0 = System.nanoTime();
        private Clock() {}
        static double nowMs() { return BASE_MS + (System.nanoTime() - NANO0) / 1e6; }
    }

    /** In memory (one process). */
    final class MemoryRecorder implements Recorder {
        private final List<Op> ops = Collections.synchronizedList(new ArrayList<>());

        public List<Op> ops() { synchronized (ops) { return new ArrayList<>(ops); } }

        @Override public Op invoke(String client, String kind, String key, double lo, double w) {
            Op op = new Op(client, kind, key, lo, w, clock(), Double.POSITIVE_INFINITY, "unknown");
            ops.add(op);
            return op;
        }

        @Override public void complete(Op op, Boolean result) {
            if (result == null) return;
            double at = clock();
            synchronized (ops) { op.ret = at; op.res = result ? "true" : "false"; }
        }
    }

    /**
     * Appends {@code i} / {@code r} lines to a file, one write per event, so a client that is killed (see {@link #kill()}) leaves its
     * in-flight operations PENDING, exactly like a crash in production; torn lines are skipped by {@link Kit#parseHistory}.
     */
    final class FileRecorder implements Recorder, AutoCloseable {
        private final FileChannel ch;
        private final String proc;
        private long seq;
        private final Map<Op, Long> ids = new IdentityHashMap<>();
        private volatile boolean killed;

        public FileRecorder(Path path, String proc) throws IOException {
            this.ch = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
            this.proc = proc;
        }

        /** After a kill nothing more is written: whatever is in flight stays pending. */
        public void kill() { killed = true; }

        @Override public boolean dead() { return killed; }

        private synchronized void line(String s) {
            if (killed) return;
            try {
                ch.write(ByteBuffer.wrap(Json.utf8((s + "\n"))));
            } catch (IOException e) {
                throw new IllegalStateException("history write failed: " + e.getMessage(), e);
            }
        }

        private static String num(double d) { return Js.numStr(d); }

        @Override public synchronized Op invoke(String client, String kind, String key, double lo, double w) {
            Op op = new Op(client, kind, key, lo, w, clock(), Double.POSITIVE_INFINITY, "unknown");
            long id = ++seq;
            ids.put(op, id);
            line("[\"i\"," + Js.quote(proc) + "," + id + "," + num(op.call) + "," + Js.quote(client) + "," + Js.quote(kind) + "," + Js.quote(key) + "," + num(lo) + "," + num(w) + "]");
            return op;
        }

        @Override public synchronized void complete(Op op, Boolean result) {
            double at = clock();
            line("[\"r\"," + Js.quote(proc) + "," + ids.get(op) + "," + num(at) + "," + (result == null ? "\"unknown\"" : "\"" + result + "\"") + "]");
        }

        @Override public void close() throws IOException { ch.close(); }
    }
}
