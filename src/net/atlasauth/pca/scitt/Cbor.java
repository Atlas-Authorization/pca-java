package net.atlasauth.pca.scitt;

import net.atlasauth.pca.Json;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deterministic CBOR (RFC 8949 section 4.2.1 core deterministic encoding), the minimal profile sufficient for COSE_Sign1: unsigned and
 * negative integers (safe-integer range), byte strings, text strings, arrays, maps (keys sorted by their encoded bytes, no duplicates),
 * tags, and the booleans and null. Floats, other simple values and indefinite lengths are refused on decode, so a forged receipt that
 * uses them fails closed.
 *
 * <p>Value model: {@link Long} (any {@link Integer}/{@link Short} is accepted on encode), {@link String}, {@code byte[]}, {@link Boolean},
 * {@code null}, {@link List}, {@link Map} (keys {@link Long} or {@link String}; decode returns insertion-ordered maps) and {@link Tag}.
 * Errors are {@link IllegalArgumentException}.
 */
public final class Cbor {
    private Cbor() {}

    /** Largest integer a JavaScript number holds exactly: the profile's integer range is +-(2^53 - 1). */
    public static final long MAX_SAFE = 9007199254740991L;

    /** A CBOR tagged value (major type 6), used for the COSE_Sign1 tag (18). */
    public static final class Tag {
        public final long tag;
        public final Object value;

        public Tag(long tag, Object value) { this.tag = tag; this.value = value; }
    }

    private static IllegalArgumentException err(String m) { return new IllegalArgumentException(m); }

    private static boolean isWellFormed(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) return false;
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }

    private static void head(ByteArrayOutputStream o, int major, long arg) {
        int mt = major << 5;
        if (arg < 24) { o.write(mt | (int) arg); return; }
        if (arg < 0x100) { o.write(mt | 24); o.write((int) arg); return; }
        if (arg < 0x10000) { o.write(mt | 25); o.write((int) (arg >>> 8) & 0xff); o.write((int) arg & 0xff); return; }
        if (arg < 0x100000000L) {
            o.write(mt | 26);
            for (int s = 24; s >= 0; s -= 8) o.write((int) (arg >>> s) & 0xff);
            return;
        }
        o.write(mt | 27);
        for (int s = 56; s >= 0; s -= 8) o.write((int) (arg >>> s) & 0xff);
    }

    /** An integer value of the model as a long within the safe range, or an error (a non-integral or unsafe number). */
    private static long intOf(Object v, String what) {
        long n;
        if (v instanceof Long || v instanceof Integer || v instanceof Short) n = ((Number) v).longValue();
        else if (v instanceof Double && ((Double) v) == Math.rint((Double) v) && !Double.isInfinite((Double) v)
            && Math.abs((Double) v) <= MAX_SAFE && !(((Double) v) == 0.0 && 1 / (Double) v < 0)) n = ((Double) v).longValue();
        else throw err(what);
        if (n > MAX_SAFE || n < -MAX_SAFE) throw err(what);
        return n;
    }

    private static boolean isNumber(Object v) { return v instanceof Number; }

    private static void encodeInt(ByteArrayOutputStream o, long n) {
        if (n >= 0) head(o, 0, n); else head(o, 1, -1 - n);
    }

    private static void encodeText(ByteArrayOutputStream o, String s) {
        if (!isWellFormed(s)) throw err("cbor: text string contains a lone surrogate");
        byte[] b = Json.utf8(s);
        head(o, 3, b.length);
        o.write(b, 0, b.length);
    }

    private static byte[] encodeKey(Object k) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (k instanceof Double && (Double) k == 0.0) encodeInt(o, 0); // a -0 key is the integer 0 as in a JavaScript Map
        else if (isNumber(k)) encodeInt(o, intOf(k, "cbor: bad integer map key"));
        else if (k instanceof String) encodeText(o, (String) k);
        else throw err("cbor: bad map key");
        return o.toByteArray();
    }

    /** Unsigned lexicographic comparison of two byte arrays. */
    private static int cmp(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0) return d;
        }
        return a.length - b.length;
    }

    /** Deterministically encode a CBOR value. Throws on anything outside the supported profile. */
    public static byte[] encode(Object v) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        enc(o, v);
        return o.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private static void enc(ByteArrayOutputStream o, Object v) {
        if (v == null) { o.write(0xf6); return; }
        if (v instanceof Boolean) { o.write((Boolean) v ? 0xf5 : 0xf4); return; }
        if (v instanceof Number) { encodeInt(o, intOf(v, "cbor: only safe-integer numbers are supported")); return; }
        if (v instanceof String) { encodeText(o, (String) v); return; }
        if (v instanceof byte[]) { byte[] b = (byte[]) v; head(o, 2, b.length); o.write(b, 0, b.length); return; }
        if (v instanceof List) {
            List<Object> l = (List<Object>) v;
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            for (Object x : l) enc(body, x);
            head(o, 4, l.size());
            o.write(body.toByteArray(), 0, body.size());
            return;
        }
        if (v instanceof Map) {
            Map<Object, Object> m = (Map<Object, Object>) v;
            List<byte[][]> entries = new ArrayList<>();
            for (Map.Entry<Object, Object> e : m.entrySet()) entries.add(new byte[][] {encodeKey(e.getKey()), encode(e.getValue())});
            entries.sort((x, y) -> cmp(x[0], y[0]));
            for (int i = 1; i < entries.size(); i++) {
                if (cmp(entries.get(i - 1)[0], entries.get(i)[0]) == 0) throw err("cbor: duplicate map key");
            }
            head(o, 5, m.size());
            for (byte[][] e : entries) { o.write(e[0], 0, e[0].length); o.write(e[1], 0, e[1].length); }
            return;
        }
        if (v instanceof Tag) {
            Tag t = (Tag) v;
            if (t.tag < 0 || t.tag > MAX_SAFE) throw err("cbor: bad tag");
            head(o, 6, t.tag);
            enc(o, t.value);
            return;
        }
        throw err("cbor: unsupported value");
    }

    private static final class Reader {
        final byte[] buf;
        int pos;

        Reader(byte[] buf) { this.buf = buf; }

        int octet() {
            if (pos >= buf.length) throw err("cbor: unexpected end of input");
            return buf[pos++] & 0xff;
        }

        byte[] bytes(long n) {
            if (n > buf.length - pos) throw err("cbor: unexpected end of input");
            byte[] out = Arrays.copyOfRange(buf, pos, pos + (int) n);
            pos += (int) n;
            return out;
        }

        long readUint(int n) {
            long v = 0;
            for (int i = 0; i < n; i++) {
                int b = octet();
                v = (v << 8) | b;
            }
            if (v < 0 || v > MAX_SAFE) throw err("cbor: integer out of safe range");
            return v;
        }

        long[] readHead() {
            int ib = octet();
            int major = ib >> 5;
            int info = ib & 0x1f;
            if (major == 7 && info >= 24) throw err("cbor: unsupported simple/float value");
            if (info < 24) return new long[] {major, info};
            long arg;
            switch (info) {
                case 24: arg = readUint(1); if (arg < 24) throw err("cbor: non-minimal integer"); break;
                case 25: arg = readUint(2); if (arg < 0x100) throw err("cbor: non-minimal integer"); break;
                case 26: arg = readUint(4); if (arg < 0x10000) throw err("cbor: non-minimal integer"); break;
                case 27: arg = readUint(8); if (arg < 0x100000000L) throw err("cbor: non-minimal integer"); break;
                default: throw err("cbor: unsupported additional information (indefinite/reserved)");
            }
            return new long[] {major, arg};
        }

        Object value() {
            long[] h = readHead();
            long major = h[0];
            long arg = h[1];
            switch ((int) major) {
                case 0: return arg;
                case 1:
                    if (arg >= MAX_SAFE) throw err("cbor: integer out of safe range"); // -1 - arg would fall below -(2^53 - 1)
                    return -1 - arg;
                case 2: return bytes(arg);
                case 3: {
                    byte[] b = bytes(arg);
                    try {
                        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString();
                    } catch (CharacterCodingException e) {
                        throw err("The encoded data was not valid for encoding utf-8");
                    }
                }
                case 4: {
                    List<Object> out = new ArrayList<>();
                    for (long i = 0; i < arg; i++) out.add(value());
                    return out;
                }
                case 5: {
                    Map<Object, Object> map = new LinkedHashMap<>();
                    byte[] prev = null;
                    for (long i = 0; i < arg; i++) {
                        int keyStart = pos;
                        Object key = value();
                        if (!(key instanceof Long) && !(key instanceof String)) throw err("cbor: map key must be int or text");
                        byte[] keyBytes = Arrays.copyOfRange(buf, keyStart, pos);
                        if (prev != null && cmp(prev, keyBytes) >= 0) throw err("cbor: map keys not canonically ordered / duplicate");
                        prev = keyBytes;
                        map.put(key, value());
                    }
                    return map;
                }
                case 6: return new Tag(arg, value());
                case 7:
                    if (arg == 20) return Boolean.FALSE;
                    if (arg == 21) return Boolean.TRUE;
                    if (arg == 22) return null;
                    throw err("cbor: unsupported simple/float value");
                default: throw err("cbor: unsupported major type");
            }
        }
    }

    /** Strictly decode a single canonical CBOR value, requiring the whole buffer to be consumed. */
    public static Object decode(byte[] bytes) {
        Reader r = new Reader(bytes);
        Object v;
        try {
            v = r.value();
        } catch (StackOverflowError e) {
            throw err("Maximum call stack size exceeded");
        }
        if (r.pos != bytes.length) throw err("cbor: trailing bytes");
        return v;
    }
}
