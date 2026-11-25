package net.atlasauth.pca;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A {@link MeshWitnessStore} on one file. {@code save} writes a temp file, fsyncs it, renames it over the state file (atomic on one
 * filesystem) and fsyncs the directory, so after it returns a restarted witness loads exactly this state and a crash mid-write leaves
 * the old or the new file, never a mix. The file carries a digest of its state: {@code load} refuses damaged, edited or foreign content
 * (it throws; a witness never starts empty over it).
 */
public final class FileMeshWitnessStore implements MeshWitnessStore {
    private final Path path;

    public FileMeshWitnessStore(Path path) { this.path = path; }

    @Override public synchronized Map<String, Object> load() {
        if (!Files.exists(path)) return null;
        Object doc;
        try {
            doc = Json.parseLenient(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty");
        }
        return MeshWitnessDoc.state(doc, "FileMeshWitnessStore: the state file");
    }

    @Override public synchronized void save(Map<String, Object> state) {
        byte[] body = Json.canonicalize(MeshWitnessDoc.wrap(state)).getBytes(StandardCharsets.UTF_8);
        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
        try {
            try (FileChannel ch = PrivateFiles.openChannel(tmp, java.util.Set.of(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE))) {
                ch.write(ByteBuffer.wrap(body));
                ch.force(true);
            }
            Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            Path dir = path.toAbsolutePath().getParent();
            try (FileChannel d = FileChannel.open(dir, StandardOpenOption.READ)) {
                d.force(true);
            } catch (IOException | UnsupportedOperationException ignored) {
                // some platforms cannot fsync a directory; the rename above is already atomic
            }
        } catch (IOException e) {
            throw new IllegalStateException("FileMeshWitnessStore: could not write the state file: " + e.getMessage(), e);
        }
    }
}

/** The stored form shared by the durable witness stores: {@code {v:1, state, digest}} with the digest of the state. */
final class MeshWitnessDoc {
    private MeshWitnessDoc() {}

    static Map<String, Object> wrap(Map<String, Object> state) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", StoreJs.num(1));
        m.put("state", StoreJs.deepCopy(state));
        m.put("digest", Pca.hashCanonical(state));
        return m;
    }

    /** The state of a stored document; throws (never an empty state) on a wrong shape or a failed digest. */
    static Map<String, Object> state(Object doc, String who) {
        Map<String, Object> d = StoreJs.map(doc);
        if (d == null || !StoreJs.isInt(d.get("v")) || StoreJs.lng(d.get("v")) != 1 || !(d.get("digest") instanceof String) || StoreJs.map(d.get("state")) == null) {
            throw new IllegalStateException(who + " has an unexpected shape; refusing to start empty");
        }
        Map<String, Object> st = StoreJs.map(StoreJs.deepCopy(d.get("state")));
        String digest;
        try {
            digest = Pca.hashCanonical(st);
        } catch (RuntimeException e) {
            throw new IllegalStateException(who + " fails its digest; refusing to start empty");
        }
        if (!digest.equals(d.get("digest"))) throw new IllegalStateException(who + " fails its digest; refusing to start empty");
        return st;
    }
}
