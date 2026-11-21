package net.atlasauth.pca.mpc;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;

/**
 * The wire layer of the networked MPC runner: the length-prefixed JSON frame codec with strict envelope validation, the
 * canonical hex field-element encoding, and the structured abort (NetAbort) that blames a party only when the evidence names
 * one. Sockets, TLS and the distributed protocol driver are not part of this class (see the package notes).
 */
public final class NetWire {
    private NetWire() {}

    /** Frame envelope version; a peer on another version is rejected as a version mismatch. */
    public static final int WIRE_VERSION = 2;
    /** Largest frame body accepted or produced (4 MiB). */
    public static final int MAX_FRAME_BYTES = 4 * 1024 * 1024;

    public static final Set<String> ABORT_KINDS = Set.of("timeout", "disconnect", "version", "malformed", "oversize", "duplicate", "out-of-order", "wrong-round",
        "wrong-session", "identity", "commitment", "ot-check", "mac-check", "dealer", "equivocation", "flood", "peer-abort", "local");
    private static final Set<String> FRAME_TYPES = Set.of("hello", "msg", "abort");

    /** A protocol abort; {@code blamed} is null when the evidence names no culprit (then {@code reason} explains why). */
    public static final class NetAbort extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String kind;
        public final Integer blamed;
        public final int reporter;
        public final String claimedKind;
        public final Integer claimedBlame;
        public final String reason;
        public final Object evidence;
        public final Integer deadlineMs;

        public NetAbort(String kind, Integer blamed, int reporter, String detail, String claimedKind, Integer claimedBlame, String reason, Object evidence, Integer deadlineMs) {
            super("[" + kind + "] blamed=" + (blamed == null ? "none" : blamed.toString()) + " reporter=" + reporter + ": " + detail);
            this.kind = kind;
            this.blamed = blamed;
            this.reporter = reporter;
            this.claimedKind = claimedKind;
            this.claimedBlame = claimedBlame;
            this.reason = blamed == null ? (reason != null && !reason.isEmpty() ? reason : "unattributable: the evidence available to this party does not identify a culprit") : null;
            this.evidence = evidence;
            this.deadlineMs = deadlineMs;
        }

        public NetAbort(String kind, Integer blamed, int reporter, String detail) { this(kind, blamed, reporter, detail, null, null, null, null, null); }
    }

    // ---- JSON text (JSON.stringify semantics for the value shapes the protocol uses) ----

    /** JSON text of a value with insertion-ordered maps and JavaScript string escaping. */
    public static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(v.toString());
        else if (v instanceof String) quote(sb, (String) v);
        else if (v instanceof Json.Num) sb.append(Json.canonicalize(v));
        else if (v instanceof Integer || v instanceof Long || v instanceof Short) sb.append(v.toString());
        else if (v instanceof BigInteger) sb.append(v.toString());
        else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) sb.append(','); first = false; write(sb, x); }
            sb.append(']');
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                quote(sb, (String) e.getKey());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else throw new IllegalArgumentException("stringify: unsupported value " + v.getClass().getName());
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { sb.append(c).append(s.charAt(++i)); }
                    else if (Character.isSurrogate(c)) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    /** A frame: {v, ty, sid, seq, rd, d}. Numbers are carried as parsed JSON values so they print as the sender wrote them. */
    public record Frame(Object v, String ty, String sid, Object seq, String rd, Object d) {}

    /** Length-prefixed (4-byte big-endian) JSON frame; throws when the body exceeds MAX_FRAME_BYTES. */
    public static byte[] encodeFrame(Frame f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", f.v());
        m.put("ty", f.ty());
        m.put("sid", f.sid());
        m.put("seq", f.seq());
        m.put("rd", f.rd());
        m.put("d", f.d());
        byte[] body = Json.utf8(stringify(m));
        if (body.length > MAX_FRAME_BYTES) throw new IllegalArgumentException("frame too large");
        byte[] out = new byte[4 + body.length];
        out[0] = (byte) (body.length >>> 24);
        out[1] = (byte) (body.length >>> 16);
        out[2] = (byte) (body.length >>> 8);
        out[3] = (byte) body.length;
        System.arraycopy(body, 0, out, 4, body.length);
        return out;
    }

    /** Reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix throws. */
    public static final class FrameSplitter {
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private byte[] data = new byte[0];

        public List<byte[]> push(byte[] chunk) {
            if (chunk.length > 0) {
                buf.write(chunk, 0, chunk.length);
                data = buf.toByteArray();
            }
            List<byte[]> out = new ArrayList<>();
            int off = 0;
            for (;;) {
                if (data.length - off < 4) break;
                long len = ((data[off] & 0xffL) << 24) | ((data[off + 1] & 0xffL) << 16) | ((data[off + 2] & 0xffL) << 8) | (data[off + 3] & 0xffL);
                if (len > MAX_FRAME_BYTES) throw new IllegalStateException("oversize");
                if (data.length - off < 4 + len) break;
                byte[] body = new byte[(int) len];
                System.arraycopy(data, off + 4, body, 0, (int) len);
                out.add(body);
                off += 4 + (int) len;
            }
            if (off > 0) {
                byte[] rest = new byte[data.length - off];
                System.arraycopy(data, off, rest, 0, rest.length);
                data = rest;
                buf.reset();
                buf.write(rest, 0, rest.length);
            }
            return out;
        }
    }

    // ---- envelope validation ----

    /** The JavaScript number value of a parsed JSON number (null for anything else). */
    private static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(o.toString()); } catch (NumberFormatException e) { return null; }
        }
        return null;
    }

    private static boolean safeInt(Double d) {
        return d != null && !d.isInfinite() && !d.isNaN() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0;
    }

    private static boolean negZero(Double d) { return d == 0 && 1 / d < 0; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseObject(byte[] body) {
        Object j;
        try {
            j = Json.parseLenient(new String(body, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return null;
        }
        return j instanceof Map ? (Map<String, Object>) j : null;
    }

    /** The envelope version of a body, or null when it is not a JSON object with a safe-integer v. */
    public static Long peekVersion(byte[] body) {
        Map<String, Object> o = parseObject(body);
        if (o == null) return null;
        Double v = num(o.get("v"));
        return safeInt(v) && !negZero(v) ? Long.valueOf(v.longValue()) : null;
    }

    private static boolean envelopeShapeOk(Map<String, Object> o) {
        if (o.size() != 6 || !o.containsKey("v")) return false;
        if (!(o.get("ty") instanceof String) || !FRAME_TYPES.contains((String) o.get("ty"))) return false;
        if (!(o.get("sid") instanceof String) || !(o.get("rd") instanceof String)) return false;
        Double seq = num(o.get("seq"));
        if (!safeInt(seq) || seq < 0 || negZero(seq)) return false;
        return o.containsKey("d");
    }

    /** The frame as a map when it is a well-formed envelope of the current version, else null. */
    public static Map<String, Object> parseFrame(byte[] body) {
        Map<String, Object> o = parseObject(body);
        if (o == null) return null;
        Double v = num(o.get("v"));
        if (v == null || v != WIRE_VERSION || !envelopeShapeOk(o)) return null;
        return o;
    }

    /** The peer's version when the body is a well-formed envelope of a DIFFERENT version, else null. */
    public static Long versionMismatch(byte[] body) {
        Map<String, Object> o = parseObject(body);
        if (o == null) return null;
        Double v = num(o.get("v"));
        if (v == null || !safeInt(v) || negZero(v) || v == WIRE_VERSION) return null;
        return envelopeShapeOk(o) ? Long.valueOf(v.longValue()) : null;
    }

    // ---- canonical field-element hex ----

    public static String hx(BigInteger x) { return x.toString(16); }

    private static final Pattern HEX61 = Pattern.compile("^(0|[1-9a-f][0-9a-f]{0,15})$");

    /** Canonical lowercase hex without leading zeros of an element below the field prime; null otherwise. */
    public static BigInteger unhx(Object s) {
        if (!(s instanceof String) || !HEX61.matcher((String) s).matches()) return null;
        BigInteger v = new BigInteger((String) s, 16);
        return v.compareTo(Field.PRIME) < 0 ? v : null;
    }

    public static BigInteger[] unhxArray(Object a, int len) {
        if (!(a instanceof List) || ((List<?>) a).size() != len) return null;
        BigInteger[] out = new BigInteger[len];
        for (int i = 0; i < len; i++) {
            BigInteger v = unhx(((List<?>) a).get(i));
            if (v == null) return null;
            out[i] = v;
        }
        return out;
    }
}
