package net.atlasauth.pca;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Crash-safe, tamper-evident, multi-process-safe persistent key/value state (a faithful port of the reference
 * {@code durable-state}; the on-disk format is byte-compatible with the other lanes: a directory written by one opens in another).
 *
 * <p>LAYOUT (a directory you own, mode 0700): {@code state.journal} (hash-chained records, one JSON object per line),
 * {@code state.head} (seq + hash of the last record, written AFTER the journal), {@code state.lock.<g>} (the lock: immutable
 * numbered generation files created atomically with link(2) = {@link Files#createLink}), {@code state.fence*} (operator-recovery
 * fences).
 *
 * <p>GUARANTEES: every mutation is write-temp, fsync ({@link FileChannel#force}), rename, fsync(directory): a crash leaves the old
 * or the new journal, never a torn one, and the head trails by at most one record (repaired by the next writer). No lost updates
 * across processes: every mutation runs under the exclusive generation lock; a lock is taken over only from a PROVABLY dead holder
 * on this host and PID namespace, never by age; the generation is re-checked right before every rename. A holder that is only
 * PAUSED across {@link #recover} is fenced: every record and head carries the writer's generation, and the fence recovery wrote
 * makes load refuse a late record from a released generation. Records are hash-chained (and HMAC-tagged with {@code hmacKey}); a
 * corrupt, truncated or rolled-back state makes every operation throw {@link DurableStateError}, never silently starting empty; the
 * ONLY way past is {@code recoverFromCorruption}, which quarantines the files (kept for forensics) and starts from genesis with
 * {@code recovered} true.
 *
 * <p>NOT GUARANTEED: ONE HOST and ONE PID namespace per directory (a holder on another host or namespace is never judged dead:
 * waiters time out, fail closed); a LOCAL filesystem with working hard links (probed at open: {@code link-unsupported}); a stalled
 * live holder blocks until it dies ({@code lock-timeout}); the journal is rewritten whole per mutation (small state) and compacted
 * every {@code compactEvery} records. A stored JSON {@code null} reads back as an absent key ({@link AtomicKv} uses null for absent).
 */
public final class DurableState implements AtomicKv {
    static final String DOMAIN = "pca-durable-state/v1\n";
    static final String GENESIS = "0000000000000000000000000000000000000000000000000000000000000000";
    static final int MAX_KEY = 256;
    static final String FENCE_FILE = "state.fence";
    public static final String RECOVER_CRASH_ENV = "PCA_DURABLE_TEST_RECOVER_CRASH_AT";
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern FENCE_ENTRY = Pattern.compile("state\\.fence\\.(\\d+)-([0-9a-f]+)");
    private static final Pattern LOCK_GEN = Pattern.compile("state\\.lock\\.(\\d+)");
    private static final Pattern LOCK_TMP = Pattern.compile("state\\.lock\\.tmp-(\\d+)-");
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String BOOT_ID = randomHex(12);
    private static final long SELF_PID = ProcessHandle.current().pid();

    /** The holder an operator attests is gone: copied EXACTLY from a complete holder record of a lock file (or the lock-timeout error). */
    public static final class ExpectedLockHolder {
        public final String host;
        public final long pid;
        public final String nonce;

        public ExpectedLockHolder(String host, long pid, String nonce) { this.host = host; this.pid = pid; this.nonce = nonce; }
    }

    /** A chain position: the sequence number and record hash of the last record. */
    public static final class Position {
        public final long seq;
        public final String hash;

        public Position(long seq, String hash) { this.seq = seq; this.hash = hash; }
    }

    /** Options of {@link #open}. */
    public static final class Options {
        public final String dir;
        /** Optional >= 32-byte HMAC key: records and head are tagged; forging or re-chaining then needs the key. */
        public byte[] hmacKey;
        /** Explicit recovery: quarantine corrupt/rolled-back files and start from genesis. Default false (fail closed). */
        public boolean recoverFromCorruption;
        /** Give up acquiring the lock after this long (default 10 s). */
        public long lockTimeoutMs = 10_000;
        /** Compact the journal into a checkpoint every N records (default 256, at least 2). */
        public int compactEvery = 256;
        /** Max serialised value size in UTF-16 units (default 1 MiB). */
        public int maxValueBytes = 1_048_576;
        /** Clock for record and fence timestamps (default System.currentTimeMillis). */
        public LongSupplier now;
        /** TEST ONLY: halt this process at the named point of a commit ("after-temp-write" | "after-journal-rename"). */
        public String testCrashAt;

        public Options(String dir) { this.dir = dir; }
    }

    /** Options of {@link #recover}. */
    public static final class RecoverOptions {
        public final String dir;
        /** Must be literally true: this is an out-of-band operator action, never automatic. */
        public final boolean force;
        /** An {@link ExpectedLockHolder} copied from a complete holder record, or the string "unreadable" for an unreadable/incomplete record. */
        public final Object expectedHolder;
        /** Release the LEGACY single-file {@code state.lock} of an older version (moved aside, never deleted). */
        public boolean legacyLock;

        public RecoverOptions(String dir, boolean force, Object expectedHolder) { this.dir = dir; this.force = force; this.expectedHolder = expectedHolder; }
    }

    public static final class RecoverResult {
        public final boolean released;
        /** "not-held" or "released". */
        public final String reason;
        public final String lockFile;

        RecoverResult(boolean released, String reason, String lockFile) { this.released = released; this.reason = reason; this.lockFile = lockFile; }
    }

    /** In-memory store with the same semantics and no durability (tests / one process). Values are kept as JSON text. */
    public static final class MemoryDurableKv implements AtomicKv {
        private final Map<String, String> m = new HashMap<>();

        private static Object dec(String s) { return s == null ? null : Json.parseLenient(s); }

        private static String enc(Object v) {
            try {
                return Json.stringify(v);
            } catch (RuntimeException e) {
                throw new DurableStateError("invalid", "value is not JSON-serialisable");
            }
        }

        @Override public synchronized Object get(String key) { return dec(m.get(key)); }

        @Override public synchronized void set(String key, Object value) { m.put(key, enc(value)); }

        @Override public synchronized Object update(String key, UnaryOperator<Object> fn) {
            Object next = fn.apply(dec(m.get(key)));
            if (next != null) m.put(key, enc(next));
            return dec(m.get(key));
        }

        @Override public synchronized List<String> keys() {
            List<String> ks = new ArrayList<>(m.keySet());
            Collections.sort(ks);
            return ks;
        }

        /** Every stored value, parsed. */
        public synchronized Map<String, Object> snapshot() {
            Map<String, Object> out = new LinkedHashMap<>();
            for (String k : keys()) out.put(k, dec(m.get(k)));
            return out;
        }
    }

    public static MemoryDurableKv createMemoryDurableKv() { return new MemoryDurableKv(); }

    /** Open (creating if needed) a durable state directory. Throws {@link DurableStateError} on corrupt / rolled-back state unless recovering. */
    public static DurableState open(Options opts) { return new DurableState(opts); }

    public static DurableState openDurableState(Options opts) { return open(opts); }

    public static RecoverResult recoverDurableState(RecoverOptions opts) { return recover(opts); }

    private static final class Rec {
        final long seq; final String prev; final String op; final String payload; final long ts; final Long gen; final String h; final String mac;

        Rec(long seq, String prev, String op, String payload, long ts, Long gen, String h, String mac) {
            this.seq = seq; this.prev = prev; this.op = op; this.payload = payload; this.ts = ts; this.gen = gen; this.h = h; this.mac = mac;
        }
    }

    private static final class Head {
        final long seq; final String h; final Long gen; final String mac;

        Head(long seq, String h, Long gen, String mac) { this.seq = seq; this.h = h; this.gen = gen; this.mac = mac; }
    }

    private static final class Loaded {
        final List<Rec> recs; final Map<String, String> state; final Head head;

        Loaded(List<Rec> recs, Map<String, String> state, Head head) { this.recs = recs; this.state = state; this.head = head; }
    }

    private static final class Fence {
        final long gen; final long seq; final String h;

        Fence(long gen, long seq, String h) { this.gen = gen; this.seq = seq; this.h = h; }
    }

    private static final class FenceFile {
        final String name; final long gen;

        FenceFile(String name, long gen) { this.name = name; this.gen = gen; }
    }

    private static final class Classified {
        final String kind; final Map<String, Object> body; final Object raw;

        Classified(String kind, Map<String, Object> body, Object raw) { this.kind = kind; this.body = body; this.raw = raw; }
    }

    private static final class LockTop {
        final long g; final Map<String, Object> body;

        LockTop(long g, Map<String, Object> body) { this.g = g; this.body = body; }
    }

    private final Options opts;
    private final String dir;
    private final byte[] key;
    private final long lockTimeout;
    private final int compactEvery;
    private final int maxValue;
    private final LongSupplier clock;
    private final String journalPath;
    private final String headPath;
    private final String legacyLockPath;
    private final Object mutex = new Object();
    private Position seen = new Position(0, GENESIS);
    private String heldNonce;
    private long myGen = -1;
    private final String myNs = ownNamespace();
    private final String myStart = procStartOf(SELF_PID);
    private volatile boolean recovered;

    private DurableState(Options opts) {
        this.opts = opts;
        if (opts.dir == null || opts.dir.isEmpty()) throw new DurableStateError("invalid", "dir is required");
        this.dir = opts.dir;
        this.key = opts.hmacKey;
        if (key != null && key.length < 32) throw new DurableStateError("invalid", "hmacKey must be at least 32 bytes");
        this.lockTimeout = opts.lockTimeoutMs;
        this.compactEvery = Math.max(2, opts.compactEvery);
        this.maxValue = opts.maxValueBytes;
        this.clock = opts.now != null ? opts.now : System::currentTimeMillis;
        this.journalPath = new File(dir, "state.journal").getPath();
        this.headPath = new File(dir, "state.head").getPath();
        this.legacyLockPath = new File(dir, "state.lock").getPath();
        File d = new File(dir);
        try {
            Files.createDirectories(d.toPath(), dirAttrs());
        } catch (IOException e) {
            if (!d.isDirectory()) throw new UncheckedIOException(e);
        }
        try {
            if (isPosix()) Files.setPosixFilePermissions(d.toPath(), PosixFilePermissions.fromString("rwx------"));
        } catch (Exception e) {
            // not ours to chmod (e.g. a shared parent): keep going
        }
        probeLinks();
        withLock(() -> {
            Loaded l = loadOrRecover();
            observe(l);
            Rec last = lastOf(l.recs);
            if (last != null && (l.head == null || l.head.seq != last.seq)) writeHead(last, "nothing was written");
            return null;
        });
    }

    /** True when this open quarantined corrupt state (see {@code recoverFromCorruption}). */
    public boolean recovered() { return recovered; }

    /** Highest chain position this handle has observed. */
    public Position position() { return seen; }

    /** Verify the chain from disk now; throws {@link DurableStateError} on any problem. */
    public Position verify() {
        return withLock(() -> {
            observe(load());
            return seen;
        });
    }

    @Override public Object get(String k) {
        checkKey(k);
        return withLock(() -> {
            Loaded l = load();
            observe(l);
            String v = l.state.get(k);
            return v == null ? null : Json.parseLenient(v);
        });
    }

    @Override public List<String> keys() {
        return withLock(() -> {
            Loaded l = load();
            observe(l);
            List<String> ks = new ArrayList<>(l.state.keySet());
            Collections.sort(ks);
            return ks;
        });
    }

    /** Unconditional write (still serialised and hash-chained). Prefer {@link #update} for monotone state. */
    @Override public void set(String k, Object value) {
        checkKey(k);
        String vj = encode(value);
        withLock(() -> {
            Loaded l = load();
            Rec last = lastOf(l.recs);
            if (last != null && (l.head == null || l.head.seq != last.seq)) writeHead(last, "nothing was written");
            commit(l, k, vj);
            return null;
        });
    }

    /**
     * Atomic read-modify-write: {@code fn} gets the current value (null when absent) and returns the next value, or null to leave
     * the key unchanged. Runs under the cross-process lock and must be quick. Returns the value now stored.
     */
    @Override public Object update(String k, UnaryOperator<Object> fn) {
        checkKey(k);
        return withLock(() -> {
            Loaded l = load();
            Rec last = lastOf(l.recs);
            if (last != null && (l.head == null || l.head.seq != last.seq)) writeHead(last, "nothing was written");
            String cur = l.state.get(k);
            Object next = fn.apply(cur == null ? null : Json.parseLenient(cur));
            if (next == null) return cur == null ? null : Json.parseLenient(cur);
            String vj = encode(next);
            if (!vj.equals(cur)) commit(l, k, vj);
            return Json.parseLenient(vj);
        });
    }

    // ---- encoding, keys, hashing ----

    private static Rec lastOf(List<Rec> recs) { return recs.isEmpty() ? null : recs.get(recs.size() - 1); }

    private String encode(Object value) {
        String s;
        try {
            s = Json.stringify(value);
        } catch (RuntimeException e) {
            throw new DurableStateError("invalid", "value is not JSON-serialisable");
        }
        if (s.length() > maxValue) throw new DurableStateError("too-large", "value exceeds maxValueBytes=" + maxValue);
        return s;
    }

    private static void checkKey(String k) {
        if (k == null || k.isEmpty() || k.length() > MAX_KEY || k.indexOf('\n') >= 0) throw new DurableStateError("invalid", "key must be 1..256 chars without newlines");
    }

    private String macOf(String msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return hex(mac.doFinal(Json.utf8(msg)));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean macEq(String a, String b) { return a.length() == b.length() && MessageDigest.isEqual(Json.utf8(a), Json.utf8(b)); }

    private static String recHash(long seq, String prev, String op, String payload, long ts, Long gen) {
        List<Object> arr = new ArrayList<>();
        arr.add(seq); arr.add(prev); arr.add(op); arr.add(payload); arr.add(ts);
        if (gen != null) arr.add(gen);
        return sha(DOMAIN + Json.stringify(arr));
    }

    private static String headMsg(long seq, String h, Long gen) { return gen == null ? "head\n" + seq + "\n" + h : "head\n" + seq + "\n" + h + "\n" + gen; }

    private static String recJson(Rec r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("seq", r.seq); m.put("prev", r.prev); m.put("op", r.op); m.put("payload", r.payload); m.put("ts", r.ts);
        if (r.gen != null) m.put("gen", r.gen);
        m.put("h", r.h);
        if (r.mac != null) m.put("mac", r.mac);
        return Json.stringify(m);
    }

    // ---- loading and verifying ----

    private Head readHead() {
        if (!new File(headPath).exists()) return null;
        Object o;
        try {
            o = Json.parseLenient(readText(headPath));
        } catch (IllegalArgumentException e) {
            throw new DurableStateError("corrupt", "state.head is not valid JSON");
        }
        Map<?, ?> m = o instanceof Map ? (Map<?, ?>) o : null;
        boolean ok = m != null && safeInt(m.get("seq")) && lng(m.get("seq")) >= 0 && !IntentJs.isNegZero(IntentJs.num(m.get("seq"))) && isHex64(m.get("h"))
            && (!m.containsKey("gen") || isGen(m.get("gen")));
        if (!ok) throw new DurableStateError("corrupt", "state.head has an invalid shape");
        Head head = new Head(lng(m.get("seq")), (String) m.get("h"), m.containsKey("gen") ? Long.valueOf(lng(m.get("gen"))) : null, m.get("mac") instanceof String ? (String) m.get("mac") : null);
        if (key != null && (head.mac == null || !macEq(head.mac, macOf(headMsg(head.seq, head.h, head.gen))))) {
            throw new DurableStateError("key-mismatch", "state.head MAC does not verify (wrong key or forged head)");
        }
        return head;
    }

    private static Rec parseLine(String line, int i) {
        Object o;
        try {
            o = Json.parseLenient(line);
        } catch (IllegalArgumentException e) {
            throw new DurableStateError("corrupt", "journal line " + (i + 1) + " is not valid JSON");
        }
        Map<?, ?> m = o instanceof Map ? (Map<?, ?>) o : null;
        boolean ok = m != null && safeInt(m.get("seq")) && isHex64(m.get("prev")) && ("set".equals(m.get("op")) || "checkpoint".equals(m.get("op"))) && m.get("payload") instanceof String
            && safeInt(m.get("ts")) && !IntentJs.isNegZero(IntentJs.num(m.get("ts"))) && isHex64(m.get("h")) && (!m.containsKey("gen") || isGen(m.get("gen")));
        if (!ok) throw new DurableStateError("corrupt", "journal line " + (i + 1) + " has an invalid shape");
        return new Rec(lng(m.get("seq")), (String) m.get("prev"), (String) m.get("op"), (String) m.get("payload"), lng(m.get("ts")), m.containsKey("gen") ? Long.valueOf(lng(m.get("gen"))) : null,
            (String) m.get("h"), m.get("mac") instanceof String ? (String) m.get("mac") : null);
    }

    private Loaded load() {
        Head head = readHead();
        List<Fence> fences = readFences(dir);
        if (!new File(journalPath).exists()) {
            if (head != null && head.seq > 0) throw new DurableStateError("rollback", "state.journal is missing but state.head records seq " + head.seq);
            for (Fence f : fences) {
                if (f.seq > 0) throw new DurableStateError("rollback", "state.journal is missing but operator recovery cut it at seq " + f.seq);
            }
            if (seen.seq > 0) throw new DurableStateError("rollback", "state was deleted while open");
            return new Loaded(new ArrayList<>(), new LinkedHashMap<>(), head);
        }
        List<String> lines = new ArrayList<>(Arrays.asList(readText(journalPath).split("\n", -1)));
        if (!lines.get(lines.size() - 1).isEmpty()) throw new DurableStateError("corrupt", "journal does not end with a newline (torn or truncated)");
        lines.remove(lines.size() - 1);
        List<Rec> recs = new ArrayList<>();
        Map<String, String> state = new LinkedHashMap<>();
        String prevHash = GENESIS;
        long prevSeq = 0;
        long prevGen = 0;
        for (int i = 0; i < lines.size(); i++) {
            Rec rec = parseLine(lines.get(i), i);
            if (i == 0) {
                if (rec.op.equals("set") && (rec.seq != 1L || !rec.prev.equals(GENESIS))) throw new DurableStateError("corrupt", "journal does not start at genesis");
                if (rec.op.equals("checkpoint") && rec.seq < 1) throw new DurableStateError("corrupt", "bad checkpoint seq");
            } else {
                if (rec.seq != prevSeq + 1) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": sequence gap");
                if (!rec.prev.equals(prevHash)) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": hash chain broken");
            }
            if (!recHash(rec.seq, rec.prev, rec.op, rec.payload, rec.ts, rec.gen).equals(rec.h)) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": record hash mismatch (edited)");
            if (key != null) {
                if (rec.mac == null || !macEq(rec.mac, macOf(rec.h))) throw new DurableStateError("key-mismatch", "journal line " + (i + 1) + ": MAC does not verify (wrong key or forged record)");
            } else if (rec.mac != null) {
                throw new DurableStateError("key-mismatch", "journal is MAC-tagged but no hmacKey was supplied");
            }
            long rg = rec.gen == null ? 0L : rec.gen;
            if (rg < prevGen) {
                throw new DurableStateError("corrupt", "journal line " + (i + 1) + " (seq " + rec.seq + ") was written by lock generation " + rg + ", older than generation " + prevGen + " of an earlier record: a stale writer's record (refused)");
            }
            for (Fence f : fences) {
                if (rec.seq > f.seq && rg < f.gen) {
                    throw new DurableStateError("corrupt", "journal line " + (i + 1) + " (seq " + rec.seq + ") was written by lock generation " + rg + ", but operator recovery fenced generations below " + f.gen + " after seq " + f.seq
                        + ": a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)");
                }
            }
            prevGen = rg;
            if (rec.op.equals("checkpoint")) {
                Object entries;
                try {
                    entries = Json.parseLenient(rec.payload);
                } catch (IllegalArgumentException e) {
                    throw new DurableStateError("corrupt", "checkpoint payload is not JSON");
                }
                if (!(entries instanceof List)) throw new DurableStateError("corrupt", "checkpoint payload is not an array");
                state.clear();
                for (Object e : (List<?>) entries) {
                    if (!(e instanceof List) || ((List<?>) e).size() != 2 || !(((List<?>) e).get(0) instanceof String) || !(((List<?>) e).get(1) instanceof String)) {
                        throw new DurableStateError("corrupt", "checkpoint entry is malformed");
                    }
                    state.put((String) ((List<?>) e).get(0), (String) ((List<?>) e).get(1));
                }
            } else {
                int nl = rec.payload.indexOf('\n');
                if (nl < 1) throw new DurableStateError("corrupt", "journal line " + (i + 1) + ": malformed payload");
                state.put(rec.payload.substring(0, nl), rec.payload.substring(nl + 1));
            }
            recs.add(rec);
            prevHash = rec.h;
            prevSeq = rec.seq;
        }
        Rec last = lastOf(recs);
        long lastSeq = last == null ? 0L : last.seq;
        for (Fence f : fences) {
            if (lastSeq < f.seq) throw new DurableStateError("rollback", "journal is at seq " + lastSeq + " but operator recovery cut it at seq " + f.seq + " (truncation, or a stale writer replaced it)");
            Rec atCut = null;
            for (Rec r : recs) if (r.seq == f.seq) { atCut = r; break; }
            if (f.seq > 0 && atCut != null && !atCut.h.equals(f.h)) {
                throw new DurableStateError("corrupt", "journal record at seq " + f.seq + " is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)");
            }
        }
        if (head != null) {
            long hg = head.gen == null ? 0L : head.gen;
            if (lastSeq < head.seq) throw new DurableStateError("rollback", "journal is at seq " + lastSeq + " but state.head recorded seq " + head.seq + " (truncation or older copy)");
            if (last != null && (last.gen == null ? 0L : last.gen) < hg && (lastSeq == head.seq + 1 || (lastSeq == head.seq && !last.h.equals(head.h)))) {
                throw new DurableStateError("corrupt", "journal tail (seq " + lastSeq + ") was written by lock generation " + (last.gen == null ? 0L : last.gen) + ", older than generation " + hg + " that wrote state.head: a stale writer replaced the journal (refused)");
            }
            boolean staleHead = false;
            if (lastSeq > head.seq + 1) {
                boolean fenced = false;
                for (Fence f : fences) if (hg < f.gen && head.seq <= f.seq && lastSeq > f.seq) { fenced = true; break; }
                boolean present = false;
                for (Rec r : recs) if (r.seq == head.seq && r.h.equals(head.h)) { present = true; break; }
                staleHead = fenced && present;
            }
            if (lastSeq > head.seq + 1 && !staleHead) throw new DurableStateError("corrupt", "journal (seq " + lastSeq + ") is more than one record ahead of state.head (seq " + head.seq + ")");
            if (last != null) {
                if (lastSeq == head.seq && !last.h.equals(head.h)) throw new DurableStateError("corrupt", "journal tail does not match state.head");
                if (lastSeq == head.seq + 1 && !last.prev.equals(head.h)) throw new DurableStateError("corrupt", "journal tail is not chained from state.head");
            }
        } else if (lastSeq > 1) {
            throw new DurableStateError("rollback", "state.head is missing but the journal is at seq " + lastSeq);
        }
        if (last != null) {
            if (last.seq < seen.seq) throw new DurableStateError("rollback", "state moved backwards from seq " + seen.seq + " to " + last.seq + " while open");
            if (last.seq == seen.seq && !last.h.equals(seen.hash)) throw new DurableStateError("rollback", "state forked at seq " + last.seq + " while open");
        } else if (seen.seq > 0) {
            throw new DurableStateError("rollback", "state was emptied while open");
        }
        return new Loaded(recs, state, head);
    }

    private void quarantine() {
        String tag = clock.getAsLong() + "-" + randomHex(3);
        assertLockHeld("nothing was written"); // a writer that lost the lock must not move a newer holder's files aside
        String fencePath = new File(dir, FENCE_FILE).getPath();
        List<FenceFile> oldEntries = fenceEntryFiles(dir);
        if (new File(fencePath).exists() || !oldEntries.isEmpty()) {
            if (new File(fencePath).exists()) link(fencePath + ".quarantine-" + tag, fencePath);
            Map<String, Object> gf = new LinkedHashMap<>();
            gf.put("gen", myGen); gf.put("seq", 0L); gf.put("h", GENESIS); gf.put("from", myGen - 1); gf.put("t", clock.getAsLong());
            Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("v", 1L); doc.put("fences", Collections.singletonList(gf));
            atomicWrite(fencePath, Json.stringify(doc) + "\n", null, false);
            for (FenceFile e : oldEntries) move(new File(dir, e.name).getPath(), new File(dir, e.name + ".quarantine-" + tag).getPath());
        }
        for (String p : new String[] {journalPath, headPath}) if (new File(p).exists()) move(p, p + ".quarantine-" + tag);
        fsyncDir(dir);
        seen = new Position(0, GENESIS);
        recovered = true;
    }

    private Loaded loadOrRecover() {
        try {
            return load();
        } catch (DurableStateError e) {
            if (!opts.recoverFromCorruption) throw e;
            quarantine();
            return load();
        }
    }

    private void observe(Loaded l) {
        Rec last = lastOf(l.recs);
        if (last != null && last.seq >= seen.seq) seen = new Position(last.seq, last.h);
    }

    // ---- the lock: immutable numbered generation files ----

    private String lockFile(long g) { return new File(dir, "state.lock." + g).getPath(); }

    /** Highest numbered generation: (g, body); g = 0 when there is none; a null body means unreadable. */
    private LockTop topLock() {
        long g = -1;
        for (long x : lockGenerations(dir)) if (x > g) g = x;
        return g >= 1 ? new LockTop(g, readBody(lockFile(g))) : new LockTop(0, null);
    }

    private boolean holderDead(Map<String, Object> b, long legacyAgeMs) {
        if (b == null) return legacyAgeMs > 1000; // an unreadable legacy file (torn by an old version) older than 1 s
        Object pid = b.get("pid");
        if (!hostname().equals(b.get("host")) || !(pid instanceof Long)) return false; // another host: cannot judge, never break
        Object ns = b.get("ns");
        if (ns != null && !ns.equals(myNs)) return false; // another PID namespace: cannot judge, never break
        if (!pidAlive((Long) pid)) return true;
        Object start = b.get("start");
        if (start instanceof String) {
            String cur = procStartOf((Long) pid);
            if (cur != null && !cur.equals(start)) return true; // the pid was reused by a different process
        }
        return false;
    }

    /** Create generation g atomically with its body. false = somebody else created it first. */
    private boolean createGen(long g, Map<String, Object> body) {
        String tmp = new File(dir, "state.lock.tmp-" + SELF_PID + "-" + randomHex(6)).getPath();
        Map<String, Object> full = new LinkedHashMap<>(body);
        full.put("t", System.currentTimeMillis());
        writeNew(tmp, Json.stringify(full));
        try {
            Files.createLink(Paths.get(lockFile(g)), Paths.get(tmp));
            return true;
        } catch (FileAlreadyExistsException e) {
            return false;
        } catch (IOException | UnsupportedOperationException e) {
            throw new DurableStateError("invalid", "the state directory's filesystem cannot create the lock atomically (link: " + e.getClass().getSimpleName() + ")");
        } finally {
            quietDelete(tmp);
        }
    }

    private void gcLocks(long keepFrom) {
        try {
            String[] names = new File(dir).list();
            if (names == null) return;
            for (String f : names) {
                Matcher m = LOCK_GEN.matcher(f);
                if (m.matches()) {
                    if (parseLong(m.group(1), Long.MAX_VALUE) < keepFrom) quietDelete(new File(dir, f).getPath());
                } else if (f.startsWith("state.lock.tmp-")) {
                    Matcher t = LOCK_TMP.matcher(f);
                    long pid = t.find() ? parseLong(t.group(1), 0L) : 0L;
                    if (pid > 0 && !pidAlive(pid)) quietDelete(new File(dir, f).getPath());
                }
            }
        } catch (Exception e) {
            // best effort
        }
    }

    /** Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics. */
    private void probeLinks() {
        String a = new File(dir, "state.probe-" + SELF_PID + "-" + randomHex(6)).getPath();
        String b = a + ".lnk";
        try {
            writeNew(a, "probe");
            Files.createLink(Paths.get(b), Paths.get(a));
            boolean second;
            try {
                Files.createLink(Paths.get(b), Paths.get(a));
                second = false;
            } catch (FileAlreadyExistsException e) {
                second = true;
            } catch (Exception e) {
                second = false;
            }
            if (!second) throw new IllegalStateException("link(2) is not atomic/exclusive here");
            int nlink;
            try {
                nlink = ((Number) Files.getAttribute(Paths.get(a), "unix:nlink")).intValue();
            } catch (Exception e) {
                nlink = 2; // no unix view on this runtime: the exclusive-create probe above is the evidence
            }
            if (nlink != 2) throw new IllegalStateException("link(2) is not atomic/exclusive here");
        } catch (Exception e) {
            String what = e instanceof IllegalStateException ? e.getMessage() : e.getClass().getSimpleName();
            throw new DurableStateError("link-unsupported", "the state directory's filesystem does not provide working hard links with exclusive-create semantics (" + what + "); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE");
        } finally {
            quietDelete(a);
            quietDelete(b);
        }
    }

    private <T> T withLock(Supplier<T> f) {
        synchronized (mutex) {
            return withLockLocked(f);
        }
    }

    private String desc(Map<String, Object> b) {
        if (b == null) return "an unreadable holder record";
        Object nonce = b.get("nonce");
        if (b.get("pid") == null || b.get("host") == null || !(nonce instanceof String) || ((String) nonce).isEmpty()) {
            return "an incomplete holder record (pid=" + (b.get("pid") == null ? "?" : b.get("pid")) + " host=" + (b.get("host") == null ? "?" : b.get("host")) + " nonce="
                + (nonce instanceof String && !((String) nonce).isEmpty() ? nonce : "?") + "); release it with expectedHolder: 'unreadable'";
        }
        return "holder pid=" + b.get("pid") + " host=" + b.get("host") + " nonce=" + nonce + (b.get("ns") != null && !b.get("ns").equals(myNs) ? " (another PID namespace)" : "");
    }

    private <T> T withLockLocked(Supplier<T> f) {
        String nonce = randomHex(12);
        boolean mustFence = false;
        long deadline = System.currentTimeMillis() + lockTimeout;
        while (true) {
            LockTop top = topLock();
            long topG = top.g;
            Map<String, Object> topBody = top.body;
            boolean legacyBlocks = false;
            if (new File(legacyLockPath).exists()) {
                long age;
                try {
                    age = System.currentTimeMillis() - new File(legacyLockPath).lastModified();
                } catch (Exception e) {
                    age = 0L;
                }
                legacyBlocks = !holderDead(readBody(legacyLockPath), age);
            }
            boolean free = topG == 0L || (topBody != null && "free".equals(topBody.get("st")));
            if (!legacyBlocks && (free || holderDead(topBody, 0))) {
                Object recovering = free || topBody == null ? null : topBody.get("recovering");
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("st", "held"); body.put("pid", SELF_PID); body.put("host", hostname()); body.put("nonce", nonce); body.put("boot", BOOT_ID);
                if (myNs != null) body.put("ns", myNs);
                if (myStart != null) body.put("start", myStart);
                if (recovering != null) body.put("recovering", recovering);
                if (createGen(topG + 1, body)) {
                    if (topLock().g != topG + 1) continue; // a stale creator's re-created generation is buried below the real top: not a lock
                    myGen = topG + 1;
                    mustFence = recovering != null;
                    break;
                }
                continue; // lost the race for that generation: look again immediately
            }
            if (System.currentTimeMillis() > deadline) {
                if (legacyBlocks && (free || holderDead(topBody, 0))) {
                    throw new DurableStateError("lock-timeout", "could not acquire the state lock in " + dir + " within " + lockTimeout + " ms; blocked by " + legacyLockPath + " (legacy single-file lock of an older version; " + desc(readBody(legacyLockPath))
                        + "). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs");
                }
                throw new DurableStateError("lock-timeout", "could not acquire the state lock in " + dir + " within " + lockTimeout + " ms; blocked by " + lockFile(topG) + " (" + desc(topBody)
                    + "). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs");
            }
            try {
                Thread.sleep(5L + RANDOM.nextInt(15));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new DurableStateError("lock-timeout", "interrupted while waiting for the state lock in " + dir);
            }
        }
        heldNonce = nonce;
        gcLocks(myGen - 16);
        try {
            if (mustFence) {
                // the recovery we took over may have died before (or after) writing its fence: cut and fence now, under OUR generation, before loading
                testCrashPoint("takeover-after-lock");
                writeFence(dir, myGen - 1, () -> testCrashPoint("takeover-after-fence-temp"));
            }
            return f.get();
        } finally {
            heldNonce = null;
            try {
                Map<String, Object> free = new LinkedHashMap<>();
                free.put("st", "free");
                createGen(myGen + 1, free); // release; a live holder is never superseded, so this cannot lose a race
                gcLocks(myGen - 15);
            } catch (Exception e) {
                // the lock stays "held" by a process about to be judged dead or alive by its pid: still safe
            }
        }
    }

    /** Immediately before EVERY rename this writer makes: this handle's generation must still be the highest and must still name us. */
    private void assertLockHeld(String outcome) {
        LockTop t = topLock();
        if (heldNonce == null || t.g != myGen || t.body == null || !"held".equals(t.body.get("st")) || !heldNonce.equals(t.body.get("nonce"))) {
            throw new DurableStateError("lock-lost", "the state lock is no longer held by this writer (generation " + myGen + ", highest " + t.g + " " + (t.body != null ? String.valueOf(t.body.get("st")) : "unreadable") + "); " + outcome);
        }
    }

    private void commit(Loaded l, String keyName, String valueJson) {
        Rec last = lastOf(l.recs);
        long seq = (last == null ? 0L : last.seq) + 1;
        String prev = last == null ? GENESIS : last.h;
        String payload = keyName + "\n" + valueJson;
        long ts = clock.getAsLong();
        String h = recHash(seq, prev, "set", payload, ts, myGen);
        Rec rec = new Rec(seq, prev, "set", payload, ts, myGen, h, key != null ? macOf(h) : null);
        List<Rec> all = new ArrayList<>(l.recs);
        all.add(rec);
        if (all.size() > compactEvery) {
            // compact: ONE checkpoint at the same seq the new record would have, chained from the current tail, carrying the full state
            Map<String, String> next = new LinkedHashMap<>(l.state);
            next.put(keyName, valueJson);
            List<String> ks = new ArrayList<>(next.keySet());
            ks.sort(Comparator.naturalOrder());
            List<Object> entries = new ArrayList<>();
            for (String k : ks) entries.add(new ArrayList<Object>(Arrays.asList(k, next.get(k))));
            String cpPayload = Json.stringify(entries);
            long cts = clock.getAsLong();
            String ch = recHash(seq, prev, "checkpoint", cpPayload, cts, myGen);
            all = new ArrayList<>();
            all.add(new Rec(seq, prev, "checkpoint", cpPayload, cts, myGen, ch, key != null ? macOf(ch) : null));
        }
        Rec tail = all.get(all.size() - 1);
        StringBuilder sb = new StringBuilder();
        for (Rec r : all) sb.append(recJson(r)).append('\n');
        // journal first (atomic), head second (atomic): a crash between leaves the head one record behind (repaired by the next writer)
        atomicWrite(journalPath, sb.toString(), () -> assertLockHeld("nothing was written"), "after-temp-write".equals(opts.testCrashAt));
        if ("after-journal-rename".equals(opts.testCrashAt)) Runtime.getRuntime().halt(137);
        writeHead(tail, "the journal record (seq " + tail.seq + ") was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)");
        seen = new Position(tail.seq, tail.h);
    }

    /** Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal. */
    private void writeHead(Rec tail, String outcome) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("seq", tail.seq); m.put("h", tail.h); m.put("gen", myGen);
        if (key != null) m.put("mac", macOf(headMsg(tail.seq, tail.h, myGen)));
        atomicWrite(headPath, Json.stringify(m) + "\n", () -> assertLockHeld(outcome), false);
    }

    // ---- small helpers ----

    static String hex(byte[] b) {
        char[] c = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            c[i * 2] = HEX_DIGITS[v >>> 4];
            c[i * 2 + 1] = HEX_DIGITS[v & 15];
        }
        return new String(c);
    }

    static String randomHex(int nBytes) {
        byte[] b = new byte[nBytes];
        RANDOM.nextBytes(b);
        return hex(b);
    }

    private static String sha(String s) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(Json.utf8(s)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long parseLong(String s, long dflt) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    private static boolean isHex64(Object o) { return o instanceof String && HEX64.matcher((String) o).matches(); }

    private static boolean safeInt(Object o) { return IntentJs.isSafeInteger(o); }

    private static boolean isGen(Object o) { return safeInt(o) && lng(o) >= 1; }

    private static long lng(Object o) { return IntentJs.lng(o); }

    private static String readText(String path) {
        try {
            return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void quietDelete(String path) {
        try {
            Files.deleteIfExists(Paths.get(path));
        } catch (Exception e) {
            // best effort: an orphan temp is harmless
        }
    }

    private static void move(String from, String to) {
        try {
            Files.move(Paths.get(from), Paths.get(to), StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void link(String newLink, String existing) {
        try {
            Files.createLink(Paths.get(newLink), Paths.get(existing));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static boolean isPosix() { return FileSystems.getDefault().supportedFileAttributeViews().contains("posix"); }

    private static FileAttribute<?>[] fileAttrs() throws IOException { return PrivateFiles.fileAttributes(); }

    private static FileAttribute<?>[] dirAttrs() throws IOException { return PrivateFiles.directoryAttributes(); }

    /** Create {@code path} exclusively (mode 0600), write {@code data}, fsync. */
    private static void writeNew(String path, String data) {
        Set<StandardOpenOption> o = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        try (FileChannel ch = FileChannel.open(Paths.get(path), o, fileAttrs())) {
            ByteBuffer buf = ByteBuffer.wrap(Json.utf8(data));
            while (buf.hasRemaining()) ch.write(buf);
            ch.force(true);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static void fsyncDir(String dir) {
        try (FileChannel ch = FileChannel.open(Paths.get(dir), StandardOpenOption.READ)) {
            ch.force(true);
        } catch (IOException e) {
            // a directory cannot be opened for fsync on Windows; everywhere else this is a real failure
            if (!System.getProperty("os.name", "").toLowerCase().contains("win")) throw new UncheckedIOException(e);
        }
    }

    /** write-temp, fsync, {@code beforeRename} check, rename, fsync(dir). A failed check removes the temp and rethrows. */
    private static void atomicWrite(String path, String data, Runnable beforeRename, boolean crashAfterTemp) {
        String tmp = path + ".tmp-" + SELF_PID + "-" + randomHex(6);
        writeNew(tmp, data);
        if (crashAfterTemp) Runtime.getRuntime().halt(137);
        if (beforeRename != null) {
            try {
                beforeRename.run();
            } catch (RuntimeException e) {
                quietDelete(tmp);
                throw e;
            }
        }
        move(tmp, path);
        String parent = new File(path).getParent();
        fsyncDir(parent == null ? "." : parent);
    }

    // ---- the host: pid, hostname, namespace, process start time ----

    /** kill(pid, 0) semantics: a process this user cannot signal still counts as alive. */
    static boolean pidAlive(long pid) {
        try {
            return ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false);
        } catch (RuntimeException e) {
            return true;
        }
    }

    /** Process start time (field 22 of /proc/&lt;pid&gt;/stat); null off Linux or when gone. */
    static String procStartOf(long pid) {
        try {
            String st = readText("/proc/" + pid + "/stat");
            return st.substring(st.lastIndexOf(')') + 2).split(" ")[19];
        } catch (Exception e) {
            return null;
        }
    }

    static String ownNamespace() {
        try {
            return Files.readSymbolicLink(Paths.get("/proc/self/ns/pid")).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static volatile String hostnameCache;

    /** The machine's hostname as the OS reports it (gethostname), not a DNS-resolved name. */
    public static String hostname() {
        String h = hostnameCache;
        if (h == null) {
            h = clean(() -> readText("/proc/sys/kernel/hostname"));
            if (h == null) {
                h = clean(() -> {
                    Process p = new ProcessBuilder("hostname").redirectErrorStream(true).start();
                    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    p.waitFor();
                    return out;
                });
            }
            if (h == null) h = clean(() -> System.getenv("HOSTNAME"));
            if (h == null) h = clean(() -> System.getenv("COMPUTERNAME"));
            if (h == null) h = clean(() -> java.net.InetAddress.getLocalHost().getHostName());
            hostnameCache = h;
        }
        return h;
    }

    private interface Thrower { String get() throws Exception; }

    private static String clean(Thrower t) {
        try {
            String s = t.get();
            if (s == null) return null;
            s = s.trim();
            return s.isEmpty() ? null : s;
        } catch (Exception e) {
            return null;
        }
    }

    /** Test-only: halt this process at a named step of operator recovery (PCA_DURABLE_TEST=1 and the env var both set). */
    private static void testCrashPoint(String point) {
        if ("1".equals(System.getenv("PCA_DURABLE_TEST")) && point.equals(System.getenv(RECOVER_CRASH_ENV))) Runtime.getRuntime().halt(137);
    }

    // ---- lock and fence files ----

    private static List<Long> lockGenerations(String dir) {
        String[] names = new File(dir).list();
        if (names == null) throw new UncheckedIOException(new IOException("cannot list " + dir));
        List<Long> out = new ArrayList<>();
        for (String f : names) {
            Matcher m = LOCK_GEN.matcher(f);
            if (m.matches()) {
                long v = parseLong(m.group(1), -1L);
                if (v >= 0) out.add(v);
            }
        }
        return out;
    }

    /** A lock body, normalised; null when the file is unreadable or not an object. */
    private static Map<String, Object> readBody(String path) {
        Object o;
        try {
            o = Json.parseLenient(readText(path));
        } catch (RuntimeException e) {
            return null;
        }
        if (!(o instanceof Map) && !(o instanceof List)) return null; // an array is an object with none of the members
        Map<?, ?> m = o instanceof Map ? (Map<?, ?>) o : new LinkedHashMap<String, Object>();
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("st", "free".equals(m.get("st")) ? "free" : "held");
        Double pid = IntentJs.num(m.get("pid"));
        if (pid != null) b.put("pid", (long) (double) pid);
        for (String k : new String[] {"host", "nonce", "start", "ns", "boot"}) if (m.get(k) instanceof String) b.put(k, m.get(k));
        if (safeInt(m.get("recovering"))) b.put("recovering", lng(m.get("recovering")));
        return b;
    }

    private static List<FenceFile> fenceEntryFiles(String dir) {
        String[] names = new File(dir).list();
        if (names == null) throw new UncheckedIOException(new IOException("cannot list " + dir));
        List<FenceFile> out = new ArrayList<>();
        for (String n : names) {
            Matcher m = FENCE_ENTRY.matcher(n);
            if (m.matches()) out.add(new FenceFile(n, parseLong(m.group(1), Long.MAX_VALUE)));
        }
        return out;
    }

    private static Fence parseFence(Object f, String where) {
        Map<?, ?> m = f instanceof Map ? (Map<?, ?>) f : null;
        boolean ok = m != null && isGen(m.get("gen")) && safeInt(m.get("seq")) && lng(m.get("seq")) >= 0 && !IntentJs.isNegZero(IntentJs.num(m.get("seq"))) && isHex64(m.get("h"));
        if (!ok) throw new DurableStateError("corrupt", where + " has an invalid entry");
        return new Fence(lng(m.get("gen")), lng(m.get("seq")), (String) m.get("h"));
    }

    private static Object readJson(String path, String name) {
        try {
            return Json.parseLenient(readText(path));
        } catch (IllegalArgumentException e) {
            throw new DurableStateError("corrupt", name + " is not valid JSON");
        }
    }

    private static boolean isOne(Object o) { Double d = IntentJs.num(o); return d != null && d == 1.0; }

    /** Every fence: the list in {@code state.fence} (absent = none) then each {@code state.fence.<gen>-<rand>} by generation. Malformed = corrupt. */
    private static List<Fence> readFences(String dir) {
        List<Fence> out = new ArrayList<>();
        String p = new File(dir, FENCE_FILE).getPath();
        if (new File(p).exists()) {
            Object o = readJson(p, "state.fence");
            if (!(o instanceof Map) || !isOne(((Map<?, ?>) o).get("v")) || !(((Map<?, ?>) o).get("fences") instanceof List)) throw new DurableStateError("corrupt", "state.fence has an invalid shape");
            for (Object f : (List<?>) ((Map<?, ?>) o).get("fences")) out.add(parseFence(f, "state.fence"));
        }
        List<FenceFile> entries = fenceEntryFiles(dir);
        entries.sort((a, b) -> a.gen != b.gen ? Long.compare(a.gen, b.gen) : a.name.compareTo(b.name));
        for (FenceFile e : entries) {
            Object o = readJson(new File(dir, e.name).getPath(), e.name);
            if (!(o instanceof Map) || !isOne(((Map<?, ?>) o).get("v"))) throw new DurableStateError("corrupt", e.name + " has an invalid shape");
            Fence f = parseFence(((Map<?, ?>) o).get("fence"), e.name);
            if (f.gen != e.gen) throw new DurableStateError("corrupt", e.name + " names generation " + e.gen + " but holds " + f.gen);
            out.add(f);
        }
        return out;
    }

    /** (seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros). */
    private static Object[] journalTail(String dir) {
        Object[] none = {0L, GENESIS};
        try {
            String last = null;
            for (String l : readText(new File(dir, "state.journal").getPath()).split("\n", -1)) if (!l.isEmpty()) last = l;
            Object o = Json.parseLenient(last == null ? "null" : last);
            if (o instanceof Map && safeInt(((Map<?, ?>) o).get("seq")) && lng(((Map<?, ?>) o).get("seq")) >= 1 && isHex64(((Map<?, ?>) o).get("h"))) return new Object[] {lng(((Map<?, ?>) o).get("seq")), ((Map<?, ?>) o).get("h")};
            return none;
        } catch (Exception e) {
            return none;
        }
    }

    /** The operator's CUT: every journal record after the tail seen NOW must come from a generation above {@code g}. Its own immutable file. */
    private static void writeFence(String dir, long g, Runnable beforeRename) {
        readFences(dir); // an unreadable fence set fails closed here too
        Object[] tail = journalTail(dir);
        Map<String, Object> fence = new LinkedHashMap<>();
        fence.put("gen", g + 1); fence.put("seq", tail[0]); fence.put("h", tail[1]); fence.put("from", g); fence.put("t", System.currentTimeMillis());
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("v", 1L); doc.put("fence", fence);
        atomicWrite(new File(dir, FENCE_FILE + "." + (g + 1) + "-" + randomHex(6)).getPath(), Json.stringify(doc) + "\n", beforeRename, false);
    }

    /** A holder record is COMPLETE only with a numeric pid, a host and a non-empty nonce. */
    @SuppressWarnings("unchecked")
    private static Classified classifyLockFile(String path) {
        Object o;
        try {
            o = Json.parseLenient(readText(path));
        } catch (RuntimeException e) {
            return new Classified("unreadable", null, null);
        }
        if (!(o instanceof Map) && !(o instanceof List)) return new Classified("unreadable", null, null);
        if (o instanceof List) return new Classified("incomplete", null, o);
        Map<String, Object> r = (Map<String, Object>) o;
        if ("free".equals(r.get("st"))) return new Classified("free", null, null);
        if (IntentJs.num(r.get("pid")) != null && r.get("host") instanceof String && r.get("nonce") instanceof String && !"".equals(r.get("nonce"))) return new Classified("complete", r, r);
        return new Classified("incomplete", null, r);
    }

    /** JS template-literal text of a number or string member. */
    private static String tmpl(Object v) {
        if (v == null) return "undefined";
        if (v instanceof String) return (String) v;
        return Json.stringify(v);
    }

    /** Is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names one, else by hostname. */
    private static boolean holderAliveHere(Object raw) {
        if (!(raw instanceof Map)) return false;
        Map<?, ?> b = (Map<?, ?>) raw;
        Double pidNum = IntentJs.num(b.get("pid"));
        if (pidNum == null) return false;
        String nsNow = ownNamespace();
        Object ns = b.get("ns");
        boolean judgeable = ns instanceof String ? nsNow != null && ns.equals(nsNow) : hostname().equals(b.get("host"));
        long pid = (long) (double) pidNum;
        if (!judgeable || !pidAlive(pid)) return false;
        Object start = b.get("start");
        if (start instanceof String) {
            String cur = procStartOf(pid);
            if (cur != null && !cur.equals(start)) return false; // the pid was reused by a different process
        }
        return true;
    }

    private static DurableStateError invalid(String msg) { return new DurableStateError("invalid", msg); }

    private static void confirmHolder(Classified c, Object exp, String path) {
        boolean unreadable = "unreadable".equals(exp);
        switch (c.kind) {
            case "unreadable":
                if (!unreadable) throw invalid(path + " is unreadable; pass expectedHolder: 'unreadable' to release it");
                break;
            case "incomplete": {
                if (!unreadable) {
                    String raw = Json.stringify(c.raw);
                    throw invalid(path + " has an incomplete holder record (" + (raw.length() > 160 ? raw.substring(0, 160) : raw) + "); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it");
                }
                if (holderAliveHere(c.raw)) {
                    Object pid = c.raw instanceof Map ? ((Map<?, ?>) c.raw).get("pid") : null;
                    throw invalid("the holder of " + path + " (pid " + tmpl(pid) + ") is alive in this PID namespace; refusing to release a live holder");
                }
                break;
            }
            case "complete": {
                Map<String, Object> b = c.body;
                String pidT = tmpl(b.get("pid"));
                if (unreadable) throw invalid(path + " is readable (holder pid=" + pidT + " host=" + b.get("host") + "); expectedHolder 'unreadable' does not match");
                ExpectedLockHolder e = (ExpectedLockHolder) exp;
                Double p = IntentJs.num(b.get("pid"));
                if (!e.host.equals(b.get("host")) || p == null || p != (double) e.pid || !e.nonce.equals(b.get("nonce"))) {
                    throw invalid("expectedHolder does not match the holder recorded in " + path + " (recorded pid=" + pidT + " host=" + b.get("host") + " nonce=" + b.get("nonce") + "); nothing was changed");
                }
                if (holderAliveHere(b)) throw invalid("the holder of " + path + " (pid " + pidT + ") is alive in this PID namespace; refusing to release a live holder");
                break;
            }
            default:
                break;
        }
    }

    private static void linkBody(String dir, String path, long gen, Map<String, Object> body, String crashPoint) {
        String tmp = new File(dir, "state.lock.tmp-" + SELF_PID + "-" + randomHex(6)).getPath();
        writeNew(tmp, Json.stringify(body));
        testCrashPoint(crashPoint);
        try {
            Files.createLink(Paths.get(new File(dir, "state.lock." + gen).getPath()), Paths.get(tmp));
        } catch (FileAlreadyExistsException e) {
            throw invalid(path + " was superseded while recovering; re-read the lock state and retry");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            quietDelete(tmp);
        }
    }

    /**
     * Operator recovery for a lock whose holder cannot be judged dead automatically (another PID namespace, a changed hostname, an
     * unreadable or incomplete top lock file, or a legacy single-file {@code state.lock}). Out of band: it takes the lock itself
     * (generation g+1, marked {@code recovering}), cuts and FENCES the released generation, then appends a "free" generation g+2. The
     * caller passes the recorded holder EXACTLY (or "unreadable"); any difference, or a holder alive in this PID namespace, is
     * refused with code {@code invalid} and nothing is changed.
     */
    public static RecoverResult recover(RecoverOptions opts) {
        if (!opts.force) throw invalid("recoverDurableState requires force: true");
        Object exp = opts.expectedHolder;
        if (!("unreadable".equals(exp) || (exp instanceof ExpectedLockHolder && !((ExpectedLockHolder) exp).nonce.isEmpty()))) {
            throw invalid("expectedHolder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'");
        }
        String dir = opts.dir;
        long g = 0;
        for (long x : lockGenerations(dir)) if (x > g) g = x;
        String path = new File(dir, "state.lock." + g).getPath();
        Classified top = g == 0 ? null : classifyLockFile(path);
        String legacyPath = new File(dir, "state.lock").getPath();
        if (opts.legacyLock) {
            if (top != null && !top.kind.equals("free")) throw invalid("legacyLock: true, but the blocking lock is the generation lock " + path + "; call recoverDurableState without legacyLock");
            if (!new File(legacyPath).exists()) return new RecoverResult(false, "not-held", null);
            Classified legacy = classifyLockFile(legacyPath);
            if (legacy.kind.equals("free")) return new RecoverResult(false, "not-held", legacyPath);
            confirmHolder(legacy, exp, legacyPath);
            // a legacy (older-version) writer stamps no generation (reads as 0): every record after the cut needs >= g + 1 >= 1
            writeFence(dir, g, null);
            move(legacyPath, new File(dir, "state.lock.legacy-recovered-" + System.currentTimeMillis() + "-" + randomHex(3)).getPath());
            fsyncDir(dir);
            return new RecoverResult(true, "released", legacyPath);
        }
        if (top == null || top.kind.equals("free")) {
            if (new File(legacyPath).exists()) {
                Classified lb = classifyLockFile(legacyPath);
                String who = lb.kind.equals("complete") ? "holder pid=" + tmpl(lb.body.get("pid")) + " host=" + lb.body.get("host") + " nonce=" + lb.body.get("nonce") : lb.kind + " holder record";
                throw invalid("the blocking lock is the legacy single-file " + legacyPath + " (" + who + "); after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')");
            }
            return top == null ? new RecoverResult(false, "not-held", null) : new RecoverResult(false, "not-held", path);
        }
        confirmHolder(top, exp, path);
        // in this order (the model DurableFence): TAKE generation g+1 (marked `recovering`), CUT + FENCE under it, RELEASE as g+2 free
        String ns = ownNamespace();
        testCrashPoint("before-lock");
        String start = procStartOf(SELF_PID);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("st", "held"); body.put("pid", SELF_PID); body.put("host", hostname()); body.put("nonce", randomHex(12)); body.put("boot", BOOT_ID);
        if (ns != null) body.put("ns", ns);
        if (start != null) body.put("start", start);
        body.put("recovering", g);
        body.put("t", System.currentTimeMillis());
        linkBody(dir, path, g + 1, body, "after-lock-temp");
        testCrashPoint("after-lock");
        writeFence(dir, g, () -> testCrashPoint("after-fence-temp"));
        testCrashPoint("after-fence");
        Map<String, Object> free = new LinkedHashMap<>();
        free.put("st", "free"); free.put("t", System.currentTimeMillis()); free.put("recoveredFrom", g);
        linkBody(dir, path, g + 2, free, "after-release-temp");
        testCrashPoint("after-release");
        return new RecoverResult(true, "released", path);
    }
}
