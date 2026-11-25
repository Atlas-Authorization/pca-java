package net.atlasauth.pca.abe;

import static net.atlasauth.pca.aggsig.Oracle.bytes;
import static net.atlasauth.pca.aggsig.Oracle.bytesList;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.aggsig.Oracle;
import net.atlasauth.pca.pairing.Bls12;
import net.atlasauth.pca.pairing.Gt;
import org.junit.jupiter.api.Test;
import supranational.blst.P1;
import supranational.blst.P2;

/** Replays the TypeScript-reference corpus (test-data/ref-abe.json.gz) through the native FAME port. */
class AbeDiffTest {
    private static final String M = "ref-abe";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static BigInteger unhex(Object s) { return new BigInteger((String) s, 16); }

    private static BigInteger[] scalars(Object list) {
        List<?> l = (List<?>) list;
        BigInteger[] out = new BigInteger[l.size()];
        for (int i = 0; i < out.length; i++) out[i] = unhex(l.get(i));
        return out;
    }

    private static List<String> strings(Object list) {
        List<String> out = new ArrayList<>();
        for (Object o : (List<?>) list) out.add((String) o);
        return out;
    }

    private static List<Object> g1s(P1[] p) { List<Object> o = new ArrayList<>(); for (P1 x : p) o.add(x.compress()); return o; }

    private static List<Object> g2s(P2[] p) { List<Object> o = new ArrayList<>(); for (P2 x : p) o.add(x.compress()); return o; }

    @Test void genCorpusIsPresent() {
        java.nio.file.Path p = Oracle.genPath(M);
        String ci = System.getenv("CI");
        String msg = "secret oracle corpus missing: " + p + " (generate with gen-secret-corpus.sh or set PCA_SECRET_CORPUS_DIR)";
        if ("true".equals(ci) || "1".equals(ci)) org.junit.jupiter.api.Assertions.assertTrue(java.nio.file.Files.exists(p), msg);
        else org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.exists(p), msg);
    }

    @Test void fame() throws Exception {
        Oracle.each(M, "fame", a -> {
            AbePolicy.Result n = AbePolicy.normalize(a.get(0));
            if (!n.ok()) throw new IllegalArgumentException(n.reason);
            List<String> attrs = strings(a.get(1));
            Map<String, Object> s = m(a.get(2));
            Fame.Master ms = Fame.setup(scalars(s.get("a")), scalars(s.get("b")), scalars(s.get("d")));
            List<BigInteger> sg = List.of(scalars(s.get("sigma")));
            Fame.Key key = Fame.keygen(ms.msk, attrs, scalars(s.get("r")), sg, unhex(s.get("sigmaPrime")));
            Fame.Encapsulation e = Fame.encrypt(ms.mpk, n.tree, scalars(s.get("s")));
            byte[] dec = Fame.decrypt(key, n.tree, e.ct);
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("h", List.of(ms.mpk.h1.compress(), ms.mpk.h2.compress()));
            o.put("t", List.of(ms.mpk.t1, ms.mpk.t2));
            o.put("mskg", g1s(ms.msk.g));
            o.put("k0", g2s(key.k0));
            o.put("kp", g1s(key.kp));
            Map<String, Object> ka = new LinkedHashMap<>();
            for (Map.Entry<String, P1[]> en : key.attrs.entrySet()) ka.put(en.getKey(), g1s(en.getValue()));
            o.put("key", ka);
            o.put("ct0", g2s(e.ct.ct0));
            List<Object> rows = new ArrayList<>();
            for (P1[] r : e.ct.rows) rows.add(g1s(r));
            o.put("rows", rows);
            o.put("k", e.k);
            o.put("dec", dec);
            return o;
        });
    }

    @Test void gtIsElement() throws Exception { Oracle.each(M, "gtIsElement", a -> Gt.isElement(bytes(a.get(0)))); }
    @Test void gtPow() throws Exception { Oracle.each(M, "gtPow", a -> Gt.pow(bytes(a.get(0)), unhex(a.get(1)))); }
    @Test void gtMul() throws Exception { Oracle.each(M, "gtMul", a -> Gt.mul(bytes(a.get(0)), bytes(a.get(1)))); }

    @Test void pairingProduct() throws Exception {
        Oracle.each(M, "pairingProduct", a -> {
            List<P1> p = new ArrayList<>();
            List<P2> q = new ArrayList<>();
            for (byte[] b : bytesList(a.get(0))) p.add(Bls12.decodeG1(b));
            for (byte[] b : bytesList(a.get(1))) q.add(Bls12.decodeG2(b));
            return Gt.pairingProduct(p, q);
        });
    }

    @Test void normalizePolicy() throws Exception { Oracle.each(M, "normalizePolicy", a -> AbePolicy.normalize(a.get(0)).toJson()); }
    @Test void satisfies() throws Exception { Oracle.each(M, "satisfies", a -> AbePolicy.satisfies(m(a.get(0)), new HashSet<>(strings(a.get(1))))); }
    @Test void policyAttributes() throws Exception { Oracle.each(M, "policyAttributes", a -> AbePolicy.policyAttributes(m(a.get(0)))); }
    @Test void parseCiphertext() throws Exception { Oracle.each(M, "parseCiphertext", a -> Abe.parseCiphertext(a.get(0))); }
    @Test void decrypt() throws Exception { Oracle.each(M, "decrypt", a -> Abe.decrypt(a.get(0), a.get(1))); }
    @Test void decryptText() throws Exception { Oracle.each(M, "decryptText", a -> Abe.decryptText(a.get(0), a.get(1))); }
    @Test void decryptWithCapability() throws Exception { Oracle.each(M, "decryptWithCapability", a -> Abe.decryptWithCapability(a.get(0), a.get(1))); }

    @Test void encryptAccepts() throws Exception {
        Oracle.each(M, "encryptAccepts", a -> { Abe.encryptForPolicy(a.get(0), a.get(1), "x"); return true; });
    }

    @Test void keygenForAttributes() throws Exception {
        Oracle.each(M, "keygenForAttributes", a -> new ArrayList<>(m(Abe.keygenForAttributes(a.get(0), strings(a.get(1))).get("attrs")).keySet()));
    }

    @Test void keygenForCapability() throws Exception {
        Oracle.each(M, "keygenForCapability", a -> {
            Map<String, Object> k = Abe.keygenForCapability(a.get(0), m(a.get(1)), strings(a.get(2)), m(a.get(3)));
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("holder", k.get("holder"));
            o.put("attrs", new ArrayList<>(m(k.get("attrs")).keySet()));
            return o;
        });
    }

    @Test void capabilityAttributes() throws Exception {
        Oracle.each(M, "capabilityAttributes", a -> new ArrayList<>(new java.util.TreeSet<>(Abe.capabilityAttributes(m(a.get(0)), m(a.get(1))))));
    }
}
