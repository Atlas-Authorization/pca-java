package net.atlasauth.pca.scitt;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A file-backed {@link ScittLogStore}: one append-only file of checksummed transactions (entry plus its new subtree hashes), fsynced
 * before {@link #append} returns, so a crash leaves either the whole transaction or none of it. A torn final record is discarded on
 * open; corruption anywhere else throws {@code store_corrupt}. SINGLE PROCESS: it does not lock the file, so run one writer per
 * directory (use a database-backed store for a fleet). The file format is byte-identical to the TypeScript reference.
 */
public final class FileScittLogStore implements ScittLogStore, AutoCloseable {
    private static final class Off {
        final long at;
        final int len;

        Off(long at, int len) { this.at = at; this.len = len; }
    }

    private final Map<String, byte[]> nodes = new HashMap<>();
    private final List<Off> offsets = new ArrayList<>();
    private long end;
    private final RandomAccessFile file;

    private FileScittLogStore(RandomAccessFile file) { this.file = file; }

    /** Open (creating if absent) the log file at {@code path} and rebuild the index. */
    public static FileScittLogStore open(Path path) {
        try {
            net.atlasauth.pca.PrivateFiles.ensureFile(path); // created owner-only; the plain handle below only opens it
            FileScittLogStore s = new FileScittLogStore(new RandomAccessFile(path.toFile(), "rw"));
            try {
                s.load();
            } catch (RuntimeException e) {
                s.close();
                throw e;
            }
            return s;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override public synchronized void close() {
        try {
            file.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private byte[] read(long at, long len) throws IOException {
        byte[] b = new byte[(int) len];
        int got = 0;
        file.seek(at);
        while (got < len) {
            int n = file.read(b, got, (int) len - got);
            if (n <= 0) break;
            got += n;
        }
        return got == len ? b : Arrays.copyOf(b, got);
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long u32(byte[] b, int at) { return ByteBuffer.wrap(b).getInt(at) & 0xffffffffL; }

    private void load() throws IOException {
        long total = file.length();
        long pos = 0;
        while (pos < total) {
            byte[] head = read(pos, 4);
            long len = head.length == 4 ? u32(head, 0) : -1;
            long recEnd = pos + 4 + len + 32;
            if (len < 6 || recEnd > total) {
                discardTail(pos, recEnd > total);
                return;
            }
            byte[] payload = read(pos + 4, len);
            byte[] sum = read(pos + 4 + len, 32);
            if (!MessageDigest.isEqual(sha256(payload), sum)) {
                discardTail(pos, recEnd == total);
                return;
            }
            long entryLen = u32(payload, 0);
            long p = 4 + entryLen;
            if (p + 2 > len) throw new ScittLogError("store_corrupt", "a log record has an inconsistent length");
            int count = ByteBuffer.wrap(payload).getShort((int) p) & 0xffff;
            p += 2;
            if (p + (long) count * 40 != len) throw new ScittLogError("store_corrupt", "a log record has an inconsistent length");
            offsets.add(new Off(pos + 8, (int) entryLen));
            for (int i = 0; i < count; i++, p += 40) {
                int ip = (int) p;
                nodes.put((payload[ip] & 0xff) + ":" + u32(payload, ip + 1), Arrays.copyOfRange(payload, ip + 8, ip + 40));
            }
            pos = recEnd;
        }
        end = pos;
    }

    private void discardTail(long pos, boolean isTail) throws IOException {
        if (!isTail) throw new ScittLogError("store_corrupt", "the log file is corrupt at offset " + pos);
        file.setLength(pos);
        file.getFD().sync();
        end = pos;
    }

    @Override public synchronized long size() { return offsets.size(); }

    @Override public synchronized byte[] getEntry(long index) {
        if (index < 0 || index >= offsets.size()) return null;
        Off o = offsets.get((int) index);
        try {
            return read(o.at, o.len);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override public synchronized byte[] getNode(long level, long index) {
        byte[] h = nodes.get(level + ":" + index);
        return h == null ? null : h.clone();
    }

    @Override public synchronized boolean append(long expectedSize, byte[] entry, List<StoredNode> nodeList) {
        if (offsets.size() != expectedSize) return false;
        for (StoredNode n : nodeList) {
            if (n.level < 0 || n.level > 255 || n.index < 0 || n.index > 0xffffffffL || n.hash == null || n.hash.length != 32) {
                throw new ScittLogError("store_corrupt", "a subtree node is malformed");
            }
        }
        ByteBuffer payload = ByteBuffer.allocate(4 + entry.length + 2 + nodeList.size() * 40);
        payload.putInt(entry.length);
        payload.put(entry);
        payload.putShort((short) nodeList.size());
        for (StoredNode n : nodeList) {
            payload.put((byte) n.level);
            payload.putInt((int) n.index);
            payload.put(new byte[3]);
            payload.put(n.hash);
        }
        byte[] pl = payload.array();
        ByteBuffer rec = ByteBuffer.allocate(4 + pl.length + 32);
        rec.putInt(pl.length);
        rec.put(pl);
        rec.put(sha256(pl));
        try {
            file.seek(end);
            file.write(rec.array());
            file.getFD().sync();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        offsets.add(new Off(end + 8, entry.length));
        for (StoredNode n : nodeList) nodes.put(n.level + ":" + n.index, n.hash.clone());
        end += rec.capacity();
        return true;
    }
}
