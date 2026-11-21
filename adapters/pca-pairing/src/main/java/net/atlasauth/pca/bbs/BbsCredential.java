package net.atlasauth.pca.bbs;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/**
 * PCA layer: a capability as a multi-message BBS credential with selective disclosure. The message vector is
 * {@code iss}, {@code sub}, then one message per caveat named {@code cav:<i>:<type>} whose value is the strict-canonical JSON
 * of the caveat; each message's octets are {@code utf8(name) || 0x00 || utf8(value)}. Credentials, attributes and
 * presentations are JSON maps with the same member names as the TypeScript types.
 */
public final class BbsCredential {
    private BbsCredential() {}

    /** UTF-8 with U+FFFD for an unpaired surrogate (what a JavaScript TextEncoder produces). */
    private static byte[] utf8(String s) {
        try {
            ByteBuffer b = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE)
                    .replaceWith(new byte[] {(byte) 0xEF, (byte) 0xBF, (byte) 0xBD}).encode(java.nio.CharBuffer.wrap(s));
            byte[] out = new byte[b.remaining()];
            b.get(out);
            return out;
        } catch (java.nio.charset.CharacterCodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] encodeAttribute(Object name, Object value) {
        if (!(name instanceof String) || !(value instanceof String)) throw new IllegalArgumentException("attribute name and value must be strings");
        if (((String) name).indexOf('\0') >= 0) throw new IllegalArgumentException("attribute name must not contain NUL");
        byte[] n = utf8((String) name);
        byte[] v = utf8((String) value);
        byte[] out = new byte[n.length + 1 + v.length];
        System.arraycopy(n, 0, out, 0, n.length);
        System.arraycopy(v, 0, out, n.length + 1, v.length);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("not an object");
        return (Map<String, Object>) o;
    }

    private static List<?> asList(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("not an array");
        return (List<?>) o;
    }

    private static byte[] encode(Object attr) {
        Map<String, Object> a = asMap(attr);
        return encodeAttribute(a.get("name"), a.get("value"));
    }

    private static List<byte[]> encodeAll(Object attrs) {
        List<byte[]> out = new ArrayList<>();
        for (Object a : asList(attrs)) out.add(encode(a));
        return out;
    }

    private static Map<String, Object> attr(int index, String name, Object value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", new Json.Num(Integer.toString(index)));
        m.put("name", name);
        m.put("value", value);
        return m;
    }

    /** The ordered attribute vector for a capability: issuer, holder, then each caveat. */
    public static List<Map<String, Object>> capabilityAttributes(Map<String, Object> capability) {
        List<Map<String, Object>> attrs = new ArrayList<>();
        attrs.add(attr(0, "iss", capability.get("issuer")));
        attrs.add(attr(1, "sub", capability.get("holder")));
        if (capability.get("caveats") instanceof List) {
            List<?> cs = (List<?>) capability.get("caveats");
            for (int i = 0; i < cs.size(); i++) {
                Map<String, Object> cv = asMap(cs.get(i));
                attrs.add(attr(i + 2, "cav:" + i + ":" + cv.get("type"), Json.canonicalizeStrict(cv)));
            }
        }
        return attrs;
    }

    /** Sign a capability's attributes as a BBS credential; {@code header} is optional application context (null = empty). */
    public static Map<String, Object> issueCapabilityCredential(Map<String, Object> capability, BigInteger sk, byte[] pk, byte[] header) {
        List<Map<String, Object>> attributes = capabilityAttributes(capability);
        byte[] hdr = header == null ? new byte[0] : header;
        byte[] signature = Bbs.sign(sk, pk, hdr, encodeAll(attributes));
        Map<String, Object> cred = new LinkedHashMap<>();
        cred.put("issuerPublicKey", Keys.b64u(pk));
        cred.put("header", Keys.b64u(hdr));
        cred.put("attributes", attributes);
        cred.put("signature", Keys.b64u(signature));
        return cred;
    }

    /** Verify a whole credential against its issuer key (every attribute). Never throws. */
    public static boolean verifyCredential(Map<String, Object> cred) {
        byte[] pk;
        byte[] header;
        byte[] signature;
        try {
            pk = Keys.unb64u((String) cred.get("issuerPublicKey"));
            header = Keys.unb64u((String) cred.get("header"));
            signature = Keys.unb64u((String) cred.get("signature"));
        } catch (RuntimeException e) {
            return false;
        }
        try {
            return Bbs.verify(pk, signature, header, encodeAll(cred.get("attributes")));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static int indexOf(Object attr) {
        Object i = asMap(attr).get("index");
        double d = i instanceof Json.Num ? Double.parseDouble(((Json.Num) i).raw) : Double.NaN;
        if (d != Math.rint(d) || Double.isInfinite(d) || Math.abs(d) > Integer.MAX_VALUE) throw new IllegalArgumentException("attribute index is not an integer");
        return (int) d;
    }

    /** Selective-disclosure presentation revealing only the named attributes; {@code presentationHeader} binds it to a context (null = empty). The proof is randomized. */
    public static Map<String, Object> presentCredential(Map<String, Object> cred, List<String> disclose, byte[] presentationHeader) {
        byte[] pk = Keys.unb64u((String) cred.get("issuerPublicKey"));
        byte[] header = Keys.unb64u((String) cred.get("header"));
        byte[] signature = Keys.unb64u((String) cred.get("signature"));
        byte[] ph = presentationHeader == null ? new byte[0] : presentationHeader;
        Set<String> wanted = new TreeSet<>(disclose);
        List<byte[]> messages = encodeAll(cred.get("attributes"));
        List<Integer> idx = new ArrayList<>();
        List<Object> disclosed = new ArrayList<>();
        for (Object a : asList(cred.get("attributes"))) {
            if (wanted.contains(asMap(a).get("name"))) {
                idx.add(indexOf(a));
                disclosed.add(a);
            }
        }
        List<String> missing = new ArrayList<>();
        for (String w : wanted) {
            boolean found = false;
            for (Object d : disclosed) if (w.equals(asMap(d).get("name"))) found = true;
            if (!found) missing.add(w);
        }
        if (!missing.isEmpty()) throw new IllegalArgumentException("presentCredential: unknown attribute(s): " + String.join(", ", missing));
        byte[] proof = Bbs.proofGen(pk, signature, header, ph, messages, idx);
        Map<String, Object> pres = new LinkedHashMap<>();
        pres.put("issuerPublicKey", cred.get("issuerPublicKey"));
        pres.put("header", cred.get("header"));
        pres.put("presentationHeader", Keys.b64u(ph));
        pres.put("messageCount", new Json.Num(Integer.toString(asList(cred.get("attributes")).size())));
        pres.put("disclosed", disclosed);
        pres.put("proof", Keys.b64u(proof));
        return pres;
    }

    /**
     * Check a presentation. {@code pk}, {@code disclosed} and {@code presentationHeader} default (when null) to the values the presentation
     * carries; pass them to assert the verifier's own expectations. Never throws.
     */
    public static boolean verifyPresentation(Map<String, Object> pres, byte[] pk, List<Map<String, Object>> disclosed, byte[] presentationHeader) {
        byte[] pkb;
        byte[] header;
        byte[] proof;
        try {
            pkb = pk != null ? pk : Keys.unb64u((String) pres.get("issuerPublicKey"));
            header = Keys.unb64u((String) pres.get("header"));
            proof = Keys.unb64u((String) pres.get("proof"));
        } catch (RuntimeException e) {
            return false;
        }
        if (pk != null && !Keys.b64u(pk).equals(pres.get("issuerPublicKey"))) return false;
        byte[] ph;
        if (presentationHeader != null) ph = presentationHeader;
        else {
            try {
                ph = Keys.unb64u((String) pres.get("presentationHeader"));
            } catch (RuntimeException e) {
                return false;
            }
        }
        if (presentationHeader != null && presentationHeader.length > 0 && !Keys.b64u(ph).equals(pres.get("presentationHeader"))) return false;
        try {
            return verifyInner(pres, pkb, header, proof, ph, disclosed);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String key(Object x) {
        Map<String, Object> a = asMap(x);
        return indexOf(x) + "\u0000" + a.get("name") + "\u0000" + a.get("value");
    }

    private static boolean sameDisclosure(List<?> a, List<?> b) {
        if (a.size() != b.size()) return false;
        List<String> sa = new ArrayList<>();
        List<String> sb = new ArrayList<>();
        for (Object x : a) sa.add(key(x));
        for (Object x : b) sb.add(key(x));
        Collections.sort(sa);
        Collections.sort(sb);
        return sa.equals(sb);
    }

    private static boolean verifyInner(Map<String, Object> pres, byte[] pk, byte[] header, byte[] proof, byte[] ph, List<Map<String, Object>> optsDisclosed) {
        List<?> disclosed = optsDisclosed != null ? optsDisclosed : asList(pres.get("disclosed"));
        if (optsDisclosed != null && !sameDisclosure(optsDisclosed, asList(pres.get("disclosed")))) return false;
        List<Object> ordered = new ArrayList<>(disclosed);
        for (Object o : ordered) indexOf(o); // an attribute without an integer index fails closed
        Collections.sort(ordered, (x, y) -> Integer.compare(indexOf(x), indexOf(y)));
        List<byte[]> msgs = new ArrayList<>();
        List<Integer> idx = new ArrayList<>();
        for (Object o : ordered) msgs.add(encode(o));
        for (Object o : ordered) idx.add(indexOf(o));
        Object mc = pres.get("messageCount");
        double count = mc instanceof Json.Num ? Double.parseDouble(((Json.Num) mc).raw) : Double.NaN;
        for (int i : idx) if (i >= count || i < 0) return false;
        return Bbs.proofVerify(pk, proof, header, ph, msgs, idx);
    }
}
