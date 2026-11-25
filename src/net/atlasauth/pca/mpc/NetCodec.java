package net.atlasauth.pca.mpc;

import net.atlasauth.pca.Json;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.mpc.Ec.Point;

/**
 * Canonical encodings of the OT-over-network messages (one accepted string per value) and the gadget-seed agreement helpers:
 * strict base64, minimal lowercase hex field elements, subgroup-validated points, and the commitment / signed statement of the
 * gadget seed exchange.
 */
public final class NetCodec {
    private NetCodec() {}

    public static String b64(byte[] u) { return Base64.getEncoder().encodeToString(u); }

    private static final Pattern B64RE = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");

    /** Strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); {@code len} &lt; 0 means any length. */
    public static byte[] unb64(Object s, int len) {
        if (!(s instanceof String) || !B64RE.matcher((String) s).matches()) throw new IllegalArgumentException("bad base64");
        byte[] b;
        try {
            b = Base64.getDecoder().decode((String) s);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("bad base64");
        }
        if (!Base64.getEncoder().encodeToString(b).equals(s)) throw new IllegalArgumentException("non-canonical base64");
        if (len >= 0 && b.length != len) throw new IllegalArgumentException("bad length");
        return b;
    }

    public static Map<String, String> ptJ(Point p) {
        BigInteger[] xy = Ec.toAffine(p);
        return Map.of("x", NetWire.hx(xy[0]), "y", NetWire.hx(xy[1]));
    }

    private static final Pattern HEX255 = Pattern.compile("^(0|[1-9a-f][0-9a-f]{0,63})$");

    /** Canonical lowercase hex without leading zeros of an element below the curve field prime. */
    public static BigInteger hexBig(Object s) {
        if (!(s instanceof String) || !HEX255.matcher((String) s).matches()) throw new IllegalArgumentException("bad field element");
        BigInteger v = new BigInteger((String) s, 16);
        if (v.compareTo(Ec.Q) >= 0) throw new IllegalArgumentException("non-canonical field element");
        return v;
    }

    /** A point from {x, y} canonical hex, validated to be a non-identity prime-order-subgroup point. */
    public static Point jPt(Object v) {
        if (!(v instanceof Map)) throw new IllegalArgumentException("bad point");
        Map<?, ?> m = (Map<?, ?>) v;
        BigInteger x = hexBig(m.get("x"));
        BigInteger y = hexBig(m.get("y"));
        Point p = new Point(x, y, BigInteger.ONE, Ec.modFq(x.multiply(y)));
        Ec.assertInSubgroup(p, "received point");
        return p;
    }

    public static int sharingsPerTriple(int partners) { return 3 + 2 * partners; }

    /** Commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex. */
    public static String gadgetCommit(String sessionId, int party, byte[] seed) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            h.update("atlas-pca-mpc/gadget-commit".getBytes(StandardCharsets.UTF_8));
            h.update(Json.utf8(sessionId));
            h.update(Json.utf8(Integer.toString(party)));
            h.update(seed);
            return HexFormat.of().formatHex(h.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o"). */
    public static byte[] gadgetStatement(String sessionId, String round, int signer, String value) {
        List<Object> arr = new ArrayList<>();
        arr.add("atlas-pca-mpc/gadget-sig/v1");
        arr.add(sessionId);
        arr.add(round);
        arr.add(signer);
        arr.add(value);
        return Json.utf8(NetWire.stringify(arr));
    }
}
