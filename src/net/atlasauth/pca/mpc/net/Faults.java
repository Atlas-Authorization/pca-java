package net.atlasauth.pca.mpc.net;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.Frame;

/**
 * TEST-ONLY frame-level fault injection: a MALICIOUS SENDER rewriting its own outgoing frames at the application layer (duplicate,
 * reorder, skipped sequence, garbage, truncation, wrong round/session, oversize length, drop, silence, an extra field, a forged abort
 * accusation). The bytes still travel inside valid TLS, so the receiver's framing checks decide. The byte-level network adversary is
 * {@link FaultProxy}.
 */
public final class Faults {
    private Faults() {}

    public enum Kind {
        DUPLICATE("duplicate"), REORDER("reorder"), SKIP_SEQ("skip-seq"), GARBAGE("garbage"), TRUNCATE("truncate"), BITFLIP("bitflip"),
        WRONG_ROUND("wrong-round"), WRONG_SESSION("wrong-session"), OVERSIZE("oversize"), DROP("drop"), SILENT_FROM("silent-from"),
        EXTRA_FIELD("extra-field"), FALSE_ACCUSE("false-accuse");

        public final String wire;

        Kind(String wire) { this.wire = wire; }

        public static Kind of(String s) {
            for (Kind k : values()) if (k.wire.equals(s)) return k;
            throw new IllegalArgumentException("config: unknown frameFault kind " + s);
        }
    }

    /** {@code round}: the protocol round to attack; {@code to}: restrict to one recipient (null = all); {@code accuse}: for FALSE_ACCUSE, the honest party named in the forged abort. */
    public record FrameFault(Kind kind, String round, Integer to, Integer accuse) {}

    private static byte[] lengthPrefixed(byte[] body) {
        byte[] o = new byte[4 + body.length];
        o[0] = (byte) (body.length >>> 24);
        o[1] = (byte) (body.length >>> 16);
        o[2] = (byte) (body.length >>> 8);
        o[3] = (byte) body.length;
        System.arraycopy(body, 0, o, 4, body.length);
        return o;
    }

    private static Object seqPlusOne(Frame f) {
        return f.seq() instanceof Number n ? (Object) (n.longValue() + 1) : f.seq();
    }

    /** The hook to install as {@link Mesh.Config#tamper} (with unsafeTestHooks) for one malicious sender. */
    public static Function<Mesh.TamperEvent, List<byte[]>> tamperFor(FrameFault spec) {
        ConcurrentHashMap<Integer, byte[]> stash = new ConcurrentHashMap<>();
        AtomicBoolean silent = new AtomicBoolean(false);
        return ev -> {
            if (silent.get()) return List.of();
            Frame fr = ev.frame();
            boolean hit = spec.round().equals(fr.rd()) && (spec.to() == null || spec.to() == ev.to());
            if (spec.kind() == Kind.REORDER) {
                byte[] held = stash.remove(ev.to());
                if (held != null) return List.of(ev.raw(), held); // later frame first, then the held-back one
                if (hit) {
                    stash.put(ev.to(), ev.raw());
                    return List.of();
                }
                return List.of(ev.raw());
            }
            if (!hit) return List.of(ev.raw());
            switch (spec.kind()) {
                case DUPLICATE: return List.of(ev.raw(), ev.raw());
                case SKIP_SEQ: return List.of(NetWire.encodeFrame(new Frame(fr.v(), fr.ty(), fr.sid(), seqPlusOne(fr), fr.rd(), fr.d())));
                case GARBAGE: {
                    byte[] g = new byte[ev.raw().length];
                    Arrays.fill(g, (byte) 0x5a);
                    int n = g.length - 4;
                    g[0] = (byte) (n >>> 24);
                    g[1] = (byte) (n >>> 16);
                    g[2] = (byte) (n >>> 8);
                    g[3] = (byte) n;
                    return List.of(g);
                }
                case TRUNCATE: return List.of(Arrays.copyOfRange(ev.raw(), 0, Math.max(5, ev.raw().length / 2)));
                case BITFLIP: {
                    byte[] b = ev.raw().clone();
                    int i = (int) (b.length * 0.6);
                    b[i] = (byte) (b[i] ^ 0x04);
                    return List.of(b);
                }
                case WRONG_ROUND: return List.of(NetWire.encodeFrame(new Frame(fr.v(), fr.ty(), fr.sid(), fr.seq(), "zzz-" + fr.rd(), fr.d())));
                case WRONG_SESSION: return List.of(NetWire.encodeFrame(new Frame(fr.v(), fr.ty(), "not-this-session", fr.seq(), fr.rd(), fr.d())));
                case OVERSIZE: return List.of(new byte[] {0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff});
                case DROP: return List.of();
                case SILENT_FROM:
                    silent.set(true);
                    return List.of();
                case FALSE_ACCUSE: {
                    Map<String, Object> d = new LinkedHashMap<>();
                    d.put("kind", "timeout");
                    d.put("blamed", spec.accuse() == null ? 0 : spec.accuse());
                    d.put("detail", "forged accusation");
                    return List.of(NetWire.encodeFrame(new Frame(fr.v(), "abort", fr.sid(), fr.seq(), "abort", d)));
                }
                case EXTRA_FIELD: {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("v", fr.v());
                    m.put("ty", fr.ty());
                    m.put("sid", fr.sid());
                    m.put("seq", fr.seq());
                    m.put("rd", fr.rd());
                    m.put("d", fr.d());
                    m.put("x", 1);
                    return List.of(lengthPrefixed(Json.utf8(NetWire.stringify(m))));
                }
                default: return List.of(ev.raw());
            }
        };
    }
}
