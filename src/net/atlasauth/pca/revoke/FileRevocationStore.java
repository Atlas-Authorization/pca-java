package net.atlasauth.pca.revoke;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;

/**
 * A durable {@link RevocationStore} backed by one JSON file. Every change is written to a temporary file, flushed to disk, then
 * renamed over the real file, so a crash leaves either the old or the new contents, never a torn file. Single process: two
 * processes must not share one file.
 *
 * <p>Fail closed: a file that exists but cannot be read or does not hold a valid list of entries makes the constructor throw.
 * Silently starting empty would un-revoke everything.
 */
public final class FileRevocationStore implements RevocationStore {
    private static final List<String> KINDS = List.of("cap", "holder", "issuer", "prefix");
    private final Map<String, RevocationEntry> mem = new LinkedHashMap<>();
    private final Path path;

    @SuppressWarnings("unchecked")
    public FileRevocationStore(Path path) {
        this.path = path;
        if (!Files.exists(path)) return;
        Object parsed;
        try {
            parsed = Json.parseLenient(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty");
        }
        Object list = parsed instanceof Map ? ((Map<String, Object>) parsed).get("entries") : null;
        if (!(list instanceof List)) throw new IllegalStateException("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty");
        List<RevocationEntry> out = new ArrayList<>();
        for (Object e : (List<Object>) list) {
            RevocationEntry r = valid(e);
            if (r == null) throw new IllegalStateException("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty");
            out.add(r);
        }
        for (RevocationEntry e : out) mem.put(InMemoryRevocationStore.key(e.kind, e.value), e);
    }

    @SuppressWarnings("unchecked")
    private static RevocationEntry valid(Object e) {
        if (!(e instanceof Map)) return null;
        Map<String, Object> o = (Map<String, Object>) e;
        Object kind = o.get("kind"), value = o.get("value"), reason = o.get("reason");
        if (!(kind instanceof String) || !KINDS.contains(kind)) return null;
        if (!JsVal.nonEmpty(value)) return null;
        if (!(reason instanceof String)) return null;
        if (!JsVal.isFinite(o.get("revokedAt"))) return null;
        Double nb = null;
        if (o.containsKey("notBefore")) {
            if (!JsVal.isFinite(o.get("notBefore"))) return null;
            nb = JsVal.num(o.get("notBefore"));
        }
        List<String> prefix = null;
        if (kind.equals("prefix")) {
            Object p = o.get("prefix");
            if (!(p instanceof List) || ((List<Object>) p).isEmpty()) return null;
            prefix = new ArrayList<>();
            for (Object x : (List<Object>) p) {
                if (!JsVal.nonEmpty(x)) return null;
                prefix.add((String) x);
            }
            if (!String.join(",", prefix).equals(value)) return null;
        }
        return new RevocationEntry((String) kind, (String) value, prefix, (String) reason, JsVal.num(o.get("revokedAt")), nb);
    }

    private void flush() throws IOException {
        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
        List<Object> list = new ArrayList<>();
        for (RevocationEntry e : mem.values()) list.add(e.toMap());
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("v", new Json.Num("1"));
        doc.put("entries", list);
        byte[] bytes = Json.canonicalize(doc).getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = net.atlasauth.pca.PrivateFiles.openChannel(tmp, java.util.Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING))) {
            ByteBuffer buf = ByteBuffer.wrap(bytes);
            while (buf.hasRemaining()) ch.write(buf);
            ch.force(true);
        }
        try {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Apply the change to memory and flush; on a failed flush put memory back, so memory never claims more than disk. */
    private synchronized <T> T write(java.util.function.Supplier<T> change) {
        Map<String, RevocationEntry> before = new LinkedHashMap<>(mem);
        T out = change.get();
        try {
            flush();
        } catch (IOException | RuntimeException e) {
            mem.clear();
            mem.putAll(before);
            throw e instanceof RuntimeException ? (RuntimeException) e : new IllegalStateException(e);
        }
        return out;
    }

    @Override public void add(RevocationEntry e) { write(() -> mem.put(InMemoryRevocationStore.key(e.kind, e.value), e)); }

    @Override public boolean remove(String kind, String value) { return write(() -> mem.remove(InMemoryRevocationStore.key(kind, value)) != null); }

    @Override public synchronized RevocationEntry get(String kind, String value) { return mem.get(InMemoryRevocationStore.key(kind, value)); }

    @Override public synchronized List<RevocationEntry> all() { return new ArrayList<>(mem.values()); }

    @Override public void clear() { write(() -> { mem.clear(); return null; }); }
}
