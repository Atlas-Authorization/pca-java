package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Replays every case of the reference oracle for the hybrid KEM module (X25519 + ML-KEM-768/1024, X-Wing draft-09, FIPS 203 key checks):
 * 464 cases, every fn dispatched, an unhandled fn fails the test. The randomised entry points replay through the derandomised test hooks
 * with the corpus' pinned stream; a reference throw needs the native to throw (an argument a typed API cannot even receive counts as that
 * refusal). Keygen cases compare sha256 of the expanded secret key, which proves the dk layout.
 */
public class KemDiffTest {
    private static final Set<String> FNS = Set.of("constants", "hybridKemKeygen", "hybridKem1024Keygen", "hybridEncapsulate", "hybridEncapsulate1024",
        "hybridDecapsulate", "hybridDecapsulate1024", "xwingKeygen", "xwingEncapsulateDerand", "xwingEncapsulate", "xwingDecapsulate",
        "encodeHybridPublicKey", "decodeHybridPublicKey", "encodeHybridCiphertext", "decodeHybridCiphertext", "encodeXWingPublicKey",
        "decodeXWingPublicKey", "encodeXWingCiphertext", "decodeXWingCiphertext", "mlKemEncapsulationKeyCheck", "mlKemDecapsulationKeyCheck");

    /** An argument no statically typed native can receive (the reference's JavaScript type confusion). */
    private static final class Unrepresentable extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Unrepresentable(String m) { super(m); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Object dec(Object v) {
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : l(v)) out.add(dec(x)); return out; }
        if (!(v instanceof Map)) return v;
        Map<String, Object> mm = m(v);
        if (mm.size() == 1 && mm.get("$bytes") instanceof String) return Keys.unb64u((String) mm.get("$bytes"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), dec(e.getValue()));
        return out;
    }

    private static byte[] bytes(Object o) {
        if (o == null || o instanceof byte[]) return (byte[]) o;
        throw new Unrepresentable("not bytes");
    }

    /** Bytes or null: a non-bytes value reads as "not a Uint8Array" in the key checks. */
    private static byte[] bytesOrNull(Object o) { return o instanceof byte[] ? (byte[]) o : null; }

    private static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }

    /** The corpus' pinned random stream: one byte string or a list of parts to concatenate. */
    private static byte[] stream(Object o) {
        if (o instanceof byte[]) return (byte[]) o;
        if (o instanceof List) { List<byte[]> parts = new ArrayList<>(); for (Object x : l(o)) parts.add(bytes(x)); return cat(parts.toArray(new byte[0][])); }
        throw new Unrepresentable("not a stream");
    }

    private static int intOf(Object o) {
        if (o instanceof String && (o.equals("768") || o.equals("1024"))) return Integer.parseInt((String) o);
        Double d = IntentJs.num(o);
        if (d == null || d != Math.rint(d) || Math.abs(d) > Integer.MAX_VALUE) throw new Unrepresentable("not an integer");
        return (int) (double) d;
    }

    private static byte[] expandedDk(int level, byte[] d, byte[] z) {
        byte[] rng = cat(new byte[32], d, z);
        byte[] sk = (level == 768 ? Kem.hybridKemKeygenDerand(rng) : Kem.hybridKem1024KeygenDerand(rng)).secretKey();
        return Arrays.copyOfRange(sk, 32, sk.length);
    }

    private static void applySet(byte[] b, Object set) {
        if (set == null) return;
        for (Object p : l(set)) b[intOf(l(p).get(0))] = (byte) intOf(l(p).get(1));
    }

    /** {"$hybridSk"}: x || expandedDk(level, d || z), then trim, pad, set. */
    private static byte[] hybridSk(Map<String, Object> s) {
        int level = intOf(s.get("level"));
        byte[] sk = cat(bytes(s.get("x")), expandedDk(level, bytes(s.get("d")), bytes(s.get("z"))));
        if (s.get("trim") != null) sk = Arrays.copyOf(sk, sk.length - intOf(s.get("trim")));
        if (s.get("pad") != null) sk = Arrays.copyOf(sk, sk.length + intOf(s.get("pad")));
        applySet(sk, s.get("set"));
        return sk;
    }

    /** {"$mlkemDk"}: the expanded dk of d || z, patched by set, then optionally with H(ek) rewritten to match the patched embedded ek. */
    private static byte[] mlkemDk(Map<String, Object> s) {
        int level = intOf(s.get("level")), k = level == 768 ? 3 : 4;
        byte[] dk = expandedDk(level, bytes(s.get("d")), bytes(s.get("z")));
        applySet(dk, s.get("set"));
        if (Boolean.TRUE.equals(s.get("rehash"))) {
            org.bouncycastle.crypto.digests.SHA3Digest h = new org.bouncycastle.crypto.digests.SHA3Digest(256);
            h.update(dk, 384 * k, 384 * k + 32);
            h.doFinal(dk, 768 * k + 32);
        }
        return dk;
    }

    private static byte[] secretOf(Object o) {
        if (o instanceof Map && ((Map<?, ?>) o).containsKey("$hybridSk")) return hybridSk(m(m(o).get("$hybridSk")));
        if (o instanceof Map && ((Map<?, ?>) o).containsKey("$mlkemDk")) return mlkemDk(m(m(o).get("$mlkemDk")));
        return bytes(o);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static Map<String, Object> keyOut(Kem.KeyPair kp) throws Exception {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("publicKey", kp.publicKey());
        o.put("secretKeySha256", hex(MessageDigest.getInstance("SHA-256").digest(kp.secretKey())));
        o.put("secretKeyLen", kp.secretKey().length);
        return o;
    }

    private static Map<String, Object> encOut(Kem.Encapsulation e) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("ciphertext", e.ciphertext());
        o.put("sharedSecret", e.sharedSecret());
        return o;
    }

    private static Object constants() {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("HYBRID_PUBLIC_KEY_LEN", Kem.HYBRID_PUBLIC_KEY_LEN);
        o.put("HYBRID_CIPHERTEXT_LEN", Kem.HYBRID_CIPHERTEXT_LEN);
        o.put("HYBRID_SHARED_SECRET_LEN", Kem.HYBRID_SHARED_SECRET_LEN);
        o.put("HYBRID_KEM_SUITE", Kem.HYBRID_KEM_SUITE);
        o.put("XWING_SUITE", Kem.XWING_SUITE);
        o.put("XWING_SEED_LEN", Kem.XWING_SEED_LEN);
        o.put("XWING_SECRET_KEY_LEN", Kem.XWING_SECRET_KEY_LEN);
        o.put("XWING_PUBLIC_KEY_LEN", Kem.XWING_PUBLIC_KEY_LEN);
        o.put("XWING_CIPHERTEXT_LEN", Kem.XWING_CIPHERTEXT_LEN);
        o.put("XWING_SHARED_SECRET_LEN", Kem.XWING_SHARED_SECRET_LEN);
        o.put("XWING_ESEED_LEN", Kem.XWING_ESEED_LEN);
        o.put("XWING_LABEL", Kem.xwingLabel());
        o.put("HYBRID1024_PUBLIC_KEY_LEN", Kem.HYBRID1024_PUBLIC_KEY_LEN);
        o.put("HYBRID1024_CIPHERTEXT_LEN", Kem.HYBRID1024_CIPHERTEXT_LEN);
        o.put("HYBRID1024_SHARED_SECRET_LEN", Kem.HYBRID1024_SHARED_SECRET_LEN);
        o.put("HYBRID1024_KEM_SUITE", Kem.HYBRID1024_KEM_SUITE);
        return o;
    }

    private static Object call(String fn, List<?> a) throws Exception {
        Object a0 = a.size() > 0 ? a.get(0) : null, a1 = a.size() > 1 ? a.get(1) : null;
        switch (fn) {
            case "constants": return constants();
            case "hybridKemKeygen": return keyOut(Kem.hybridKemKeygenDerand(stream(a0)));
            case "hybridKem1024Keygen": return keyOut(Kem.hybridKem1024KeygenDerand(stream(a0)));
            case "hybridEncapsulate": return encOut(Kem.hybridEncapsulateDerand(bytes(a0), stream(a1)));
            case "hybridEncapsulate1024": return encOut(Kem.hybridEncapsulate1024Derand(bytes(a0), stream(a1)));
            case "hybridDecapsulate": return Kem.hybridDecapsulate(bytes(a0), secretOf(a1));
            case "hybridDecapsulate1024": return Kem.hybridDecapsulate1024(bytes(a0), secretOf(a1));
            case "xwingKeygen": return keyOut(Kem.xwingKeygen(bytes(a0)));
            case "xwingEncapsulateDerand": case "xwingEncapsulate": return encOut(Kem.xwingEncapsulateDerand(bytes(a0), stream(a1)));
            case "xwingDecapsulate": return Kem.xwingDecapsulate(bytes(a0), bytes(a1));
            case "encodeHybridPublicKey": return Kem.encodeHybridPublicKey(bytes(a0));
            case "encodeHybridCiphertext": return Kem.encodeHybridCiphertext(bytes(a0));
            case "encodeXWingPublicKey": return Kem.encodeXWingPublicKey(bytes(a0));
            case "encodeXWingCiphertext": return Kem.encodeXWingCiphertext(bytes(a0));
            case "decodeHybridPublicKey": return Kem.decodeHybridPublicKey(str(a0));
            case "decodeHybridCiphertext": return Kem.decodeHybridCiphertext(str(a0));
            case "decodeXWingPublicKey": return Kem.decodeXWingPublicKey(str(a0));
            case "decodeXWingCiphertext": return Kem.decodeXWingCiphertext(str(a0));
            case "mlKemEncapsulationKeyCheck": return Kem.mlKemEncapsulationKeyCheck(intOf(a0), bytesOrNull(a1));
            case "mlKemDecapsulationKeyCheck": return Kem.mlKemDecapsulationKeyCheck(intOf(a0), a1 instanceof Map ? secretOf(a1) : bytesOrNull(a1));
            default: throw new AssertionError("unhandled fn " + fn);
        }
    }

    private static String str(Object o) {
        if (o instanceof String) return (String) o;
        throw new Unrepresentable("not a string");
    }

    @Test void replayAllCases() throws Exception {
        List<Map<String, Object>> cases = BaseOracle.all("ref-kem");
        assertEquals(464, cases.size());
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : cases) {
            String fn = (String) c.get("fn");
            assertTrue(FNS.contains(fn), "unhandled fn " + fn);
            List<?> args = (List<?>) dec(c.get("args"));
            String d = OracleCases.diff(c, c.get("out"), unused -> call(fn, args));
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }

    /** The no-argument randomised calls are not in the corpus: keygen -> encapsulate -> decapsulate must agree, and two calls must differ. */
    @Test void randomisedRoundTrips() {
        Kem.KeyPair h = Kem.hybridKemKeygen();
        Kem.Encapsulation he = Kem.hybridEncapsulate(h.publicKey());
        assertTrue(Arrays.equals(he.sharedSecret(), Kem.hybridDecapsulate(he.ciphertext(), h.secretKey())));
        assertFalse(Arrays.equals(h.publicKey(), Kem.hybridKemKeygen().publicKey()));
        Kem.KeyPair h2 = Kem.hybridKem1024Keygen();
        Kem.Encapsulation he2 = Kem.hybridEncapsulate1024(h2.publicKey());
        assertTrue(Arrays.equals(he2.sharedSecret(), Kem.hybridDecapsulate1024(he2.ciphertext(), h2.secretKey())));
        Kem.KeyPair x = Kem.xwingKeygen();
        Kem.Encapsulation xe = Kem.xwingEncapsulate(x.publicKey());
        assertTrue(Arrays.equals(xe.sharedSecret(), Kem.xwingDecapsulate(xe.ciphertext(), x.secretKey())));
        assertNotEquals(hex(xe.ciphertext()), hex(Kem.xwingEncapsulate(x.publicKey()).ciphertext()));
    }
}
