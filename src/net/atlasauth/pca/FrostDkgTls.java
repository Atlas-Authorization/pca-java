package net.atlasauth.pca;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import net.atlasauth.pca.FrostDkgChannel.DkgChannel;
import net.atlasauth.pca.FrostDkgChannel.DkgChannelError;
import net.atlasauth.pca.FrostDkgChannel.DkgInbox;

/**
 * The transport rules of the mutual-TLS DKG channel, independent of any TLS stack: the 4-byte big-endian length framing (a frame longer
 * than the message cap is refused before any allocation and ends the link), the pinned-certificate identity rule, and the
 * {@link DkgChannel} built over authenticated links. The TLS sockets themselves are supplied by the host application: it authenticates
 * a peer (certificate pinned to a participant id, TLS 1.3), then hands this class the link's writer and feeds the received bytes to a
 * {@link FrameReader}.
 */
public final class FrostDkgTls {
    private FrostDkgTls() {}

    /** length (4 bytes, big endian) followed by the payload. */
    public static byte[] frameEncode(byte[] payload) {
        byte[] f = new byte[4 + payload.length];
        f[0] = (byte) (payload.length >>> 24); f[1] = (byte) (payload.length >>> 16); f[2] = (byte) (payload.length >>> 8); f[3] = (byte) payload.length;
        System.arraycopy(payload, 0, f, 4, payload.length);
        return f;
    }

    /**
     * Reassembles frames from arbitrary chunks of one authenticated link and hands each payload to {@code onFrame}. A frame longer than
     * the message cap is reported to {@code onOversize} (with its declared length) before any allocation, ends the reader and discards
     * everything after it.
     */
    public static final class FrameReader {
        private final Consumer<byte[]> onFrame;
        private final java.util.function.LongConsumer onOversize;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private boolean ended;

        public FrameReader(Consumer<byte[]> onFrame, java.util.function.LongConsumer onOversize) { this.onFrame = onFrame; this.onOversize = onOversize; }

        /** A reader that feeds an inbox as {@code peer}; an oversize frame fails the peer (sticky) and then calls {@code onEnd} to drop the link. */
        public static FrameReader forInbox(DkgInbox inbox, long peer, Runnable onEnd) {
            return new FrameReader(payload -> inbox.accept(peer, payload), len -> {
                inbox.fail(peer, new DkgChannelError("oversize", peer, "frame of " + len + " bytes exceeds the cap"));
                onEnd.run();
            });
        }

        public synchronized void feed(byte[] chunk) {
            if (ended) return;
            buf.write(chunk, 0, chunk.length);
            for (;;) {
                byte[] b = buf.toByteArray();
                if (b.length < 4) return;
                long len = ((b[0] & 0xffL) << 24) | ((b[1] & 0xffL) << 16) | ((b[2] & 0xffL) << 8) | (b[3] & 0xffL);
                if (len > FrostDkgChannel.DKG_MAX_MESSAGE_BYTES) {
                    ended = true;
                    onOversize.accept(len);
                    return;
                }
                if (b.length < 4 + len) return;
                byte[] payload = java.util.Arrays.copyOfRange(b, 4, 4 + (int) len);
                buf.reset();
                buf.write(b, 4 + (int) len, b.length - 4 - (int) len);
                onFrame.accept(payload);
            }
        }

        /** Bytes of an incomplete frame still held. */
        public synchronized int buffered() { return buf.size(); }
    }

    /**
     * The identity of an authenticated peer from its certificate fingerprint, or null when the link must be refused: the fingerprint is
     * not pinned, the peer's id is below this node's (the lower id dials, so a connection from a lower id is refused) or a link to that
     * peer already exists.
     */
    public static Long acceptInbound(String fingerprint, Map<String, Long> pinned, long self, Set<Long> linked) {
        Long id = fingerprint == null ? null : pinned.get(fingerprint);
        if (id == null || id < self || linked.contains(id)) return null;
        return id;
    }

    /** A way to write one framed message to an authenticated peer. */
    public interface LinkWriter { void write(byte[] frame) throws Exception; }

    /**
     * A {@link DkgChannel} over authenticated links: a write to a peer without a link is a {@code closed} error, every message is
     * encoded for the session and framed, {@code collect} reads the inbox the {@link FrameReader}s feed.
     */
    public static DkgChannel channel(long self, byte[] sessionId, List<Long> peers, Map<Long, LinkWriter> links, DkgInbox inbox, Runnable onClose) {
        List<Long> sorted = new ArrayList<>(peers);
        java.util.Collections.sort(sorted);
        return new DkgChannel() {
            private void write(long to, String kind, Object body) {
                LinkWriter w = links.get(to);
                if (w == null) throw new DkgChannelError("closed", to, "no authenticated link");
                byte[] frame = frameEncode(FrostDkgChannel.encodeDkgMessage(sessionId, kind, body));
                try { w.write(frame); } catch (Exception e) { throw new DkgChannelError("closed", to, "write failed"); }
            }
            @Override public long self() { return self; }
            @Override public List<Long> peers() { return sorted; }
            @Override public void broadcast(String kind, Object body) { for (Long p : sorted) write(p, kind, body); }
            @Override public void send(long to, String kind, Object body) {
                if (!sorted.contains(to)) throw new DkgChannelError("identity", to, "not a connected peer");
                write(to, kind, body);
            }
            @Override public Map<Long, Object> collect(String kind, List<Long> from, double timeoutMs) { return inbox.collect(kind, from, timeoutMs); }
            @Override public void close() { onClose.run(); }
        };
    }
}
