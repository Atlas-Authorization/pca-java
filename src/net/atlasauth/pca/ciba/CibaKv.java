package net.atlasauth.pca.ciba;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.ciba.CibaApproval.ApprovalStore;
import net.atlasauth.pca.ciba.CibaApproval.Versioned;

/**
 * Shared-store reference for the durable broker: a versioned {@link ApprovalStore} built on a tiny durable key-value interface that
 * needs ONE primitive, a compare-and-swap on a string (Redis, DynamoDB conditional put, SQL {@code UPDATE ... WHERE value = ?}, etcd).
 */
public final class CibaKv {
    private CibaKv() {}

    /**
     * A durable string key-value store with compare-and-swap. {@code putIfEquals(key, expected, next)} writes {@code next} only if the
     * stored value is exactly {@code expected} (null means "the key must be absent") and reports whether it wrote. It MUST be atomic
     * across every process sharing the store, and a write MUST be durable before it returns. Any failure must throw.
     */
    public interface DurableKv {
        /** The stored string, or null when absent. */
        String get(String key);
        boolean putIfEquals(String key, String expected, String next);
    }

    /** Thrown by the KV reference implementations; the broker treats any throw from the store as "no approval". */
    public static final class ApprovalStoreError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String code;

        public ApprovalStoreError(String code, String message) {
            super(message);
            this.code = code;
        }

        /** {@code corrupt_record}, {@code lock_timeout} or {@code bad_key}. */
        public String code() { return code; }
    }

    private static Versioned decode(String raw) {
        Object parsed;
        try {
            parsed = Json.parseLenient(raw);
        } catch (RuntimeException | StackOverflowError e) {
            throw new ApprovalStoreError("corrupt_record", "ciba: stored approval record is not valid JSON");
        }
        Object ver = CibaJs.member(parsed, "version");
        Double v = CibaJs.num(ver);
        if (!(parsed instanceof Map) || v == null || v != Math.rint(v) || Double.isInfinite(v) || v < 1 || !((Map<?, ?>) parsed).containsKey("value"))
            throw new ApprovalStoreError("corrupt_record", "ciba: stored approval record has no valid version");
        return new Versioned((long) (double) v, ((Map<?, ?>) parsed).get("value"));
    }

    /**
     * An {@link ApprovalStore} over a {@link DurableKv}. Each key holds {@code {version, value}} as JSON; {@code cas} re-reads the raw string,
     * checks the version, and swaps only if the raw string is still the one it read, so two processes racing on the same expected version
     * cannot both win. A stored value that is not a valid versioned record throws ({@code corrupt_record}).
     */
    public static ApprovalStore createKvApprovalStore(DurableKv kv) {
        if (kv == null) throw new IllegalArgumentException("createKvApprovalStore: `kv` with get and putIfEquals is required");
        return new ApprovalStore() {
            @Override public Versioned get(String key) {
                String raw = kv.get(key);
                return raw == null ? null : decode(raw);
            }

            @Override public boolean cas(String key, long expectedVersion, Object value) {
                String raw = kv.get(key);
                long current = raw == null ? 0 : decode(raw).version;
                if (current != expectedVersion) return false;
                String next = CibaJs.stringify(Issue.obj("version", expectedVersion + 1, "value", value));
                return kv.putIfEquals(key, raw, next);
            }
        };
    }

    /** Single-process {@link DurableKv} for tests of code that takes a KV. Not durable. */
    public static DurableKv createMemoryKv() {
        Map<String, String> m = new HashMap<>();
        return new DurableKv() {
            @Override public synchronized String get(String k) { return m.get(k); }

            @Override public synchronized boolean putIfEquals(String k, String expected, String next) {
                if (!java.util.Objects.equals(m.get(k), expected)) return false;
                m.put(k, next);
                return true;
            }
        };
    }

    /**
     * A {@link DurableKv} on a directory, safe for several processes on ONE host (and one filesystem with atomic exclusive-create and rename).
     * One file per key; each swap takes a per-key lock file (exclusive create), compares, writes a temp file and renames it over the key. A
     * process that dies while holding the lock leaves it behind: every later swap on that key then throws {@code lock_timeout} (fail closed)
     * until an operator removes the {@code .lock} file.
     */
    public static DurableKv createDirectoryKv(Path dir, long lockTimeoutMs) {
        if (lockTimeoutMs <= 0) throw new IllegalArgumentException("createDirectoryKv: lockTimeoutMs must be a positive number");
        try {
            net.atlasauth.pca.PrivateFiles.createDirectories(dir);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return new DurableKv() {
            // The key is hashed into the file name, so no key can escape the directory.
            private Path fileOf(String key) {
                if (key == null || key.isEmpty()) throw new ApprovalStoreError("bad_key", "ciba: store key must be a non-empty string");
                try {
                    byte[] h = MessageDigest.getInstance("SHA-256").digest(Json.utf8(key));
                    StringBuilder sb = new StringBuilder();
                    for (byte b : h) sb.append(String.format("%02x", b & 0xff));
                    return dir.resolve(sb.toString());
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override public String get(String key) {
                Path f = fileOf(key);
                try {
                    return Files.exists(f) ? new String(Files.readAllBytes(f), StandardCharsets.UTF_8) : null;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override public boolean putIfEquals(String key, String expected, String next) {
                Path f = fileOf(key);
                Path lock = Path.of(f + ".lock");
                long deadline = System.currentTimeMillis() + lockTimeoutMs;
                boolean locked = false;
                while (!locked) {
                    try {
                        net.atlasauth.pca.PrivateFiles.createFile(lock);
                        locked = true;
                    } catch (java.nio.file.FileAlreadyExistsException e) {
                        if (System.currentTimeMillis() >= deadline) throw new ApprovalStoreError("lock_timeout", "ciba: could not take the store lock in time");
                        try { Thread.sleep(2); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); throw new IllegalStateException(ie); }
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                }
                try {
                    String current = Files.exists(f) ? new String(Files.readAllBytes(f), StandardCharsets.UTF_8) : null;
                    if (!java.util.Objects.equals(current, expected)) return false;
                    Path tmp = Path.of(f + "." + ProcessHandle.current().pid() + ".tmp");
                    try (FileChannel ch = net.atlasauth.pca.PrivateFiles.openChannel(tmp, java.util.Set.of(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE))) {
                        ch.write(ByteBuffer.wrap(Json.utf8(next)));
                        ch.force(true); // durable before the rename publishes it
                    }
                    Files.move(tmp, f, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                    return true;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                } finally {
                    try { Files.deleteIfExists(lock); } catch (IOException ignored) { /* the lock stays: later swaps fail closed with lock_timeout */ }
                }
            }
        };
    }

    public static DurableKv createDirectoryKv(Path dir) { return createDirectoryKv(dir, 5000); }
}
