package net.atlasauth.pca.abe;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.pairing.Bls12;
import net.atlasauth.pca.pairing.Gt;
import supranational.blst.P1;
import supranational.blst.P2;

/**
 * Proof-carrying encryption: ciphertext-policy ABE (FAME, see {@link Fame}) with the payload sealed under AES-256-GCM, the
 * whole header authenticated. Keys, ciphertexts and the master keys are JSON maps with the TypeScript reference's member
 * names, so material crosses languages unchanged. Every parser is fail-closed: {@link #decrypt} returns null on any
 * deviation and never throws.
 */
public final class Abe {
    private Abe() {}

    public static final String ABE_ALG = "fame-cpabe-bls12381-type3/aes-256-gcm";
    private static final String CEK_INFO = "atlas-pca-abe/cek/v3";
    private static final int SALT_LEN = 16;
    private static final SecureRandom RNG = new SecureRandom();

    /** An invalid policy, master public key or master secret key. */
    public static final class PcaEncryptionError extends IllegalArgumentException {
        public PcaEncryptionError(String m) { super(m); }
    }

    // ---- wire helpers -------------------------------------------------------------------------

    private static final Pattern B64U = Pattern.compile("[A-Za-z0-9_-]*");

    static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    /** Canonical unpadded base64url only; null otherwise. */
    static byte[] unb64u(Object o) {
        if (!(o instanceof String) || !B64U.matcher((String) o).matches()) return null;
        try {
            byte[] b = Base64.getUrlDecoder().decode((String) o);
            return b64u(b).equals(o) ? b : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static boolean isTwo(Object o) {
        Double d = AbePolicy.num(o);
        return d != null && d == 2.0;
    }

    /** True iff the string has an unpaired UTF-16 surrogate (such strings alias each other once UTF-8 encoded). */
    static boolean illFormed(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++;
                else return true;
            } else if (Character.isLowSurrogate(c)) return true;
        }
        return false;
    }

    private static P1 readG1(Object x) {
        byte[] b = unb64u(x);
        if (b == null) return null;
        try {
            P1 p = Bls12.decodeG1(b);
            return p.is_inf() ? null : p;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static P2 readG2(Object x) {
        byte[] b = unb64u(x);
        if (b == null) return null;
        try {
            P2 p = Bls12.decodeG2(b);
            return p.is_inf() ? null : p;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static byte[] readGt(Object x) {
        byte[] b = unb64u(x);
        return b != null && Gt.isElement(b) ? b : null;
    }

    private static P1[] tri1(Object x) {
        if (!(x instanceof List) || ((List<?>) x).size() != 3) return null;
        P1[] out = new P1[3];
        for (int i = 0; i < 3; i++) if ((out[i] = readG1(((List<?>) x).get(i))) == null) return null;
        return out;
    }

    private static P2[] tri2(Object x) {
        if (!(x instanceof List) || ((List<?>) x).size() != 3) return null;
        P2[] out = new P2[3];
        for (int i = 0; i < 3; i++) if ((out[i] = readG2(((List<?>) x).get(i))) == null) return null;
        return out;
    }

    private static List<Object> enc(P1[] p) { return List.of(b64u(p[0].compress()), b64u(p[1].compress()), b64u(p[2].compress())); }

    private static List<Object> enc(P2[] p) { return List.of(b64u(p[0].compress()), b64u(p[1].compress()), b64u(p[2].compress())); }

    // ---- scalars ------------------------------------------------------------------------------

    private static BigInteger randomScalar() {
        while (true) {
            byte[] b = new byte[64];
            RNG.nextBytes(b);
            BigInteger v = Bls12.mod(Bls12.os2ip(b));
            if (v.signum() != 0) return v;
        }
    }

    private static String scalarB64(BigInteger s) { return b64u(Bls12.i2osp(s, 32)); }

    /** Exactly one encoding per scalar: 32 bytes, non-zero, and below r. */
    private static BigInteger canonicalScalar(Object enc) {
        byte[] b = unb64u(enc);
        if (b == null || b.length != 32) return null;
        BigInteger x = Bls12.os2ip(b);
        return x.signum() == 0 || x.compareTo(Bls12.R) >= 0 ? null : x;
    }

    // ---- setup / keygen -----------------------------------------------------------------------

    /** A fresh master key pair: {@code {mpk, msk}}. */
    public static Map<String, Object> setup() {
        BigInteger[] a = {randomScalar(), randomScalar()}, b = {randomScalar(), randomScalar()}, d = {randomScalar(), randomScalar(), randomScalar()};
        Fame.Master m = Fame.setup(a, b, d);
        Map<String, Object> msk = new LinkedHashMap<>();
        msk.put("v", 2L);
        msk.put("curve", "bls12-381");
        msk.put("a", List.of(scalarB64(a[0]), scalarB64(a[1])));
        msk.put("b", List.of(scalarB64(b[0]), scalarB64(b[1])));
        msk.put("g", List.of(b64u(m.msk.g[0].compress()), b64u(m.msk.g[1].compress()), b64u(m.msk.g[2].compress())));
        Map<String, Object> mpk = new LinkedHashMap<>();
        mpk.put("v", 2L);
        mpk.put("curve", "bls12-381");
        mpk.put("h", List.of(b64u(m.mpk.h1.compress()), b64u(m.mpk.h2.compress())));
        mpk.put("t", List.of(b64u(m.mpk.t1), b64u(m.mpk.t2)));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mpk", mpk);
        out.put("msk", msk);
        return out;
    }

    private static Fame.Msk parseMsk(Object o) {
        Map<String, Object> m = obj(o);
        if (m == null || !isTwo(m.get("v"))) throw new PcaEncryptionError("invalid master secret key");
        BigInteger[] a = scalarPair(m.get("a")), b = scalarPair(m.get("b"));
        P1[] g = tri1(m.get("g"));
        if (a == null || b == null || g == null) throw new PcaEncryptionError("invalid master secret key");
        return new Fame.Msk(a, b, g);
    }

    private static BigInteger[] scalarPair(Object x) {
        if (!(x instanceof List) || ((List<?>) x).size() != 2) return null;
        BigInteger[] out = new BigInteger[2];
        for (int i = 0; i < 2; i++) if ((out[i] = canonicalScalar(((List<?>) x).get(i))) == null) return null;
        return out;
    }

    private static Fame.Mpk parseMpk(Object o) {
        Map<String, Object> m = obj(o);
        if (m != null && isTwo(m.get("v")) && m.get("h") instanceof List && ((List<?>) m.get("h")).size() == 2
                && m.get("t") instanceof List && ((List<?>) m.get("t")).size() == 2) {
            List<?> h = (List<?>) m.get("h"), t = (List<?>) m.get("t");
            P2 h1 = readG2(h.get(0)), h2 = readG2(h.get(1));
            byte[] t1 = readGt(t.get(0)), t2 = readGt(t.get(1));
            if (h1 != null && h2 != null && t1 != null && t2 != null) return new Fame.Mpk(h1, h2, t1, t2);
        }
        throw new PcaEncryptionError("invalid master public key");
    }

    /** Issue a decryption key for an explicit set of attribute tokens (empty or ill-formed names are dropped). */
    public static Map<String, Object> keygenForAttributes(Object msk, Collection<String> attrs) {
        Fame.Msk m = parseMsk(msk);
        List<String> names = new ArrayList<>();
        for (String a : new LinkedHashSet<>(attrs)) if (a != null && !a.isEmpty() && !illFormed(a)) names.add(a);
        List<BigInteger> sigmas = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) sigmas.add(randomScalar());
        Fame.Key key = Fame.keygen(m, names, new BigInteger[] {randomScalar(), randomScalar()}, sigmas, randomScalar());
        Map<String, Object> as = new LinkedHashMap<>();
        for (String n : names) as.put(n, Map.of("k", enc(key.attrs.get(n))));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", 2L);
        out.put("curve", "bls12-381");
        out.put("k0", enc(key.k0));
        out.put("kp", enc(key.kp));
        out.put("attrs", as);
        return out;
    }

    /** Issue a key bound to a capability: its {@link #capabilityAttributes} plus the extra tokens; {@code holder} is recorded. */
    public static Map<String, Object> keygenForCapability(Object msk, Map<String, Object> capability, Collection<String> extra, Map<String, Object> opts) {
        Set<String> attrs = capabilityAttributes(capability, opts);
        for (String a : extra) if (a != null && !a.isEmpty()) attrs.add(a);
        Map<String, Object> key = keygenForAttributes(msk, attrs);
        if (capability.get("holder") instanceof String) key.put("holder", capability.get("holder"));
        return key;
    }

    /** An untrusted key; a malformed attribute component counts as not held. Null if K0, K' or the container is malformed. */
    private static Fame.Key parseKey(Object o) {
        Map<String, Object> k = obj(o);
        if (k == null || !isTwo(k.get("v")) || obj(k.get("attrs")) == null) return null;
        P2[] k0 = tri2(k.get("k0"));
        P1[] kp = tri1(k.get("kp"));
        if (k0 == null || kp == null) return null;
        Map<String, P1[]> attrs = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : obj(k.get("attrs")).entrySet()) {
            Map<String, Object> comp = obj(e.getValue());
            P1[] t = comp == null ? null : tri1(comp.get("k"));
            if (t != null) attrs.put(e.getKey(), t);
        }
        return new Fame.Key(k0, kp, attrs);
    }

    // ---- KDF / AEAD ---------------------------------------------------------------------------

    /** HKDF-SHA256 (RFC 5869), 32 bytes: the content-encryption key from the KEM key. */
    static byte[] kdf32(byte[] ikm, byte[] salt, String info) {
        try {
            Mac h = Mac.getInstance("HmacSHA256");
            h.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
            byte[] prk = h.doFinal(ikm);
            h.init(new SecretKeySpec(prk, "HmacSHA256"));
            h.update(Json.utf8(info));
            h.update((byte) 1);
            return h.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[][] seal(byte[] key, byte[] pt, byte[] aad) {
        try {
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad);
            byte[] out = c.doFinal(pt);
            return new byte[][] {iv, Arrays.copyOfRange(out, 0, out.length - 16), Arrays.copyOfRange(out, out.length - 16, out.length)};
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] open(byte[] key, byte[] iv, byte[] ct, byte[] tag, byte[] aad) {
        if (key.length != 32 || iv.length != 12 || tag.length != 16) return null;
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad);
            byte[] in = Arrays.copyOf(ct, ct.length + 16);
            System.arraycopy(tag, 0, in, ct.length, 16);
            return c.doFinal(in);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    private static byte[] aad(Map<String, Object> c) {
        Map<String, Object> h = new LinkedHashMap<>();
        for (String k : List.of("v", "alg", "salt", "ct0", "tree", "rows")) h.put(k, c.get(k));
        return Json.canonicalizeStrict(h).getBytes(StandardCharsets.UTF_8);
    }

    // ---- encrypt ------------------------------------------------------------------------------

    /** Encrypt so that only a key whose attributes satisfy {@code policy} opens it. Throws {@link PcaEncryptionError} on a bad policy or key. */
    public static Map<String, Object> encryptForPolicy(Object mpk, Object policy, byte[] plaintext) {
        AbePolicy.Result norm = AbePolicy.normalize(policy);
        if (!norm.ok()) throw new PcaEncryptionError("invalid policy: " + norm.reason);
        String dup = Fame.firstRepeatedAttribute(norm.tree);
        if (dup != null) throw new PcaEncryptionError("invalid policy: attribute " + Json.canonicalize(dup) + " is named by more than one leaf (single-use attributes only)");
        Fame.Mpk pk = parseMpk(mpk);
        byte[] salt = new byte[SALT_LEN];
        RNG.nextBytes(salt);
        Fame.Encapsulation e = Fame.encrypt(pk, norm.tree, new BigInteger[] {randomScalar(), randomScalar()});
        List<Object> rows = new ArrayList<>();
        for (P1[] r : e.ct.rows) rows.add(enc(r));
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("v", 2L);
        header.put("alg", ABE_ALG);
        header.put("salt", b64u(salt));
        header.put("ct0", enc(e.ct.ct0));
        header.put("tree", norm.tree);
        header.put("rows", rows);
        byte[] headerAad;
        try {
            headerAad = aad(header);
        } catch (IllegalArgumentException x) {
            throw new PcaEncryptionError("policy cannot be authenticated (header outside the canonical JSON profile)");
        }
        byte[][] s = seal(kdf32(e.k, salt, CEK_INFO), plaintext, headerAad);
        header.put("iv", b64u(s[0]));
        header.put("ct", b64u(s[1]));
        header.put("tag", b64u(s[2]));
        return header;
    }

    public static Map<String, Object> encryptForPolicy(Object mpk, Object policy, String plaintext) {
        return encryptForPolicy(mpk, policy, Json.utf8(plaintext));
    }

    /** Encrypt a JSON value (the payload layer of {@link #decryptWithCapability}). */
    public static Map<String, Object> encryptToolPayload(Object mpk, Object policy, Object payload) {
        return encryptForPolicy(mpk, policy, Json.canonicalize(payload));
    }

    // ---- parse --------------------------------------------------------------------------------

    private static Map<String, Object> parseTree(Object x, int gates, int[] budget) {
        Map<String, Object> m = obj(x);
        if (++budget[0] > AbePolicy.MAX_POLICY_NODES || m == null) return null;
        if ("leaf".equals(m.get("kind"))) {
            Object a = m.get("attr");
            if (!(a instanceof String) || ((String) a).isEmpty() || illFormed((String) a) || m.size() != 2) return null;
            return AbePolicy.leaf((String) a);
        }
        if ("gate".equals(m.get("kind"))) {
            if (gates + 1 > AbePolicy.MAX_POLICY_DEPTH || m.size() != 3) return null;
            Object t = m.get("t"), of = m.get("of");
            if (!AbePolicy.isPosInt(t) || !(of instanceof List) || ((List<?>) of).isEmpty()) return null;
            double td = AbePolicy.num(t);
            if (td > ((List<?>) of).size() || ((List<?>) of).size() >= AbePolicy.MAX_POLICY_NODES) return null;
            List<Object> kids = new ArrayList<>();
            for (Object b : (List<?>) of) {
                Map<String, Object> sub = parseTree(b, gates + 1, budget);
                if (sub == null) return null;
                kids.add(sub);
            }
            return AbePolicy.gate((long) td, kids);
        }
        return null;
    }

    private static List<Object> strTri(Object x) {
        if (!(x instanceof List) || ((List<?>) x).size() != 3) return null;
        for (Object e : (List<?>) x) if (unb64u(e) == null) return null;
        return new ArrayList<>((List<?>) x);
    }

    /** Validate an untrusted value as a ciphertext; null (fail closed) on any deviation. */
    public static Map<String, Object> parseCiphertext(Object o) {
        Map<String, Object> x = obj(o);
        if (x == null || !isTwo(x.get("v")) || !ABE_ALG.equals(x.get("alg"))) return null;
        for (String k : List.of("salt", "iv", "ct", "tag")) if (unb64u(x.get(k)) == null) return null;
        List<Object> ct0 = strTri(x.get("ct0"));
        Map<String, Object> tree = parseTree(x.get("tree"), 0, new int[1]);
        if (ct0 == null || tree == null || !(x.get("rows") instanceof List)) return null;
        List<?> rawRows = (List<?>) x.get("rows");
        if (rawRows.size() != Fame.leafCount(tree) || Fame.firstRepeatedAttribute(tree) != null) return null;
        List<Object> rows = new ArrayList<>();
        for (Object r : rawRows) {
            List<Object> t = strTri(r);
            if (t == null) return null;
            rows.add(t);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", 2L);
        out.put("alg", ABE_ALG);
        out.put("salt", x.get("salt"));
        out.put("ct0", ct0);
        out.put("tree", tree);
        out.put("rows", rows);
        out.put("iv", x.get("iv"));
        out.put("ct", x.get("ct"));
        out.put("tag", x.get("tag"));
        return out;
    }

    // ---- decrypt ------------------------------------------------------------------------------

    /** The plaintext iff the key's attributes satisfy the ciphertext's policy and the AEAD authenticates; otherwise null. Never throws. */
    @SuppressWarnings("unchecked")
    public static byte[] decrypt(Object key, Object ciphertext) {
        try {
            Map<String, Object> ct = parseCiphertext(ciphertext);
            if (ct == null) return null;
            Fame.Key pk = parseKey(key);
            if (pk == null) return null;
            byte[] salt = unb64u(ct.get("salt")), iv = unb64u(ct.get("iv")), body = unb64u(ct.get("ct")), tag = unb64u(ct.get("tag"));
            P2[] ct0 = tri2(ct.get("ct0"));
            List<P1[]> rows = new ArrayList<>();
            for (Object r : (List<Object>) ct.get("rows")) {
                P1[] t = tri1(r);
                if (t == null) return null;
                rows.add(t);
            }
            if (salt == null || iv == null || body == null || tag == null || ct0 == null) return null;
            byte[] k = Fame.decrypt(pk, (Map<String, Object>) ct.get("tree"), new Fame.Ciphertext(ct0, rows));
            if (k == null) return null;
            byte[] headerAad;
            try {
                headerAad = aad(ct);
            } catch (IllegalArgumentException e) {
                return null;
            }
            return open(kdf32(k, salt, CEK_INFO), iv, body, tag, headerAad);
        } catch (IllegalArgumentException | ArithmeticException | ClassCastException e) {
            return null;
        }
    }

    public static String decryptText(Object key, Object ciphertext) {
        byte[] pt = decrypt(key, ciphertext);
        return pt == null ? null : new String(pt, StandardCharsets.UTF_8);
    }

    /** {@code {ok:true, payload}} or {@code {ok:false, reason}}. */
    public static Map<String, Object> decryptWithCapability(Object key, Object ciphertext) {
        Map<String, Object> out = new LinkedHashMap<>();
        byte[] pt = decrypt(key, ciphertext);
        if (pt == null) {
            out.put("ok", false);
            out.put("reason", "capability does not satisfy the policy, or ciphertext is invalid");
            return out;
        }
        try {
            Object payload = Json.parseLenient(new String(pt, StandardCharsets.UTF_8));
            out.put("ok", true);
            out.put("payload", payload);
        } catch (IllegalArgumentException e) {
            out.clear();
            out.put("ok", false);
            out.put("reason", "decrypted payload is not valid JSON");
        }
        return out;
    }

    // ---- capability attributes ----------------------------------------------------------------

    private static String act(String verb, String resource) { return "act:" + Json.canonicalize(List.of(verb, resource)); }

    private static List<String> verbsOf(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof String) out.add((String) v);
        else if (v instanceof List) for (Object e : (List<?>) v) if (e instanceof String) out.add((String) e);
        return out;
    }

    /**
     * The canonical attribute set a capability possesses (in the reference's insertion order): holder, scope, and (from the ROOT only, never from a
     * delegated hop's own caveats) act/verb/resource tokens. A delegated capability gets scope/act/verb/resource tokens only
     * with a verified chain (root first, ending in the capability); a chain that fails verification yields none (fail closed).
     * {@code opts}: {@code chain}, {@code principal}, {@code pqPins}.
     */
    @SuppressWarnings("unchecked")
    public static Set<String> capabilityAttributes(Map<String, Object> cap, Map<String, Object> opts) {
        Set<String> out = new LinkedHashSet<>();
        if (cap == null) return out;
        Object scopeSource = null;
        Map<String, Object> envSource = null;
        Object chainObj = opts == null ? null : opts.get("chain");
        if (opts != null && opts.containsKey("chain")) {
            if (!(chainObj instanceof List) || ((List<?>) chainObj).isEmpty()) return out;
            List<Object> chain = (List<Object>) chainObj;
            Map<String, Object> root = obj(chain.get(0)), last = obj(chain.get(chain.size() - 1));
            if (root == null || last == null || !Objects.equals(last.get("id"), cap.get("id"))) return out;
            Object principal = opts.get("principal") != null ? opts.get("principal") : root.get("issuer");
            Map<String, Object> pins = obj(opts.get("pqPins"));
            if (!Pca.verifyChain(chain, principal instanceof String ? (String) principal : null, principal instanceof String, null, pins, null).isEmpty()) return out;
            scopeSource = root.get("caveats");
            envSource = root;
        } else if (!cap.containsKey("parent")) {
            scopeSource = cap.get("caveats");
            envSource = cap;
        }
        if (cap.get("holder") instanceof String && !((String) cap.get("holder")).isEmpty()) out.add("holder:" + cap.get("holder"));
        if (scopeSource instanceof List) {
            for (Object c : (List<?>) scopeSource) {
                Map<String, Object> cv = obj(c);
                if (cv == null) continue;
                if ("scope".equals(cv.get("type")) && cv.get("value") instanceof String) out.add("scope:" + cv.get("value"));
                if ("scopes".equals(cv.get("type")) && cv.get("values") instanceof List)
                    for (Object s : (List<?>) cv.get("values")) if (s instanceof String) out.add("scope:" + s);
            }
        }
        Map<String, Object> env = envSource == null ? null : Authorize.readEnvelope(envSource);
        if (env != null && env.get("predicates") instanceof List) {
            List<Map<String, Object>> preds = new ArrayList<>();
            for (Object p : (List<?>) env.get("predicates")) {
                if (p instanceof Map) preds.add((Map<String, Object>) p);
                else if (p instanceof List) preds.add(Map.of()); // an array is an object to the reference: it counts, and names no verb or resource
            }
            for (Map<String, Object> p : preds)
                if (p.get("resource") instanceof String) for (String v : verbsOf(p.get("verb"))) out.add(act(v, (String) p.get("resource")));
            if (preds.size() == 1) {
                Map<String, Object> p = preds.get(0);
                for (String v : verbsOf(p.get("verb"))) out.add("verb:" + v);
                if (p.get("resource") instanceof String) out.add("resource:" + p.get("resource"));
            }
        }
        return out;
    }
}
