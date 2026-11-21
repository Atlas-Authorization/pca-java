package net.atlasauth.pca.abe;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import org.junit.jupiter.api.Test;
import supranational.blst.P1;
import supranational.blst.P2;

/** FAME group elements against an independent implementation (py_ecc): setup, keygen and encrypt with fixed scalars, byte for byte. */
class FamePyeccTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static BigInteger unhex(Object s) { return new BigInteger((String) s, 16); }

    private static BigInteger[] scalars(Object list) {
        List<?> l = (List<?>) list;
        BigInteger[] out = new BigInteger[l.size()];
        for (int i = 0; i < out.length; i++) out[i] = unhex(l.get(i));
        return out;
    }

    private static String hex(byte[] b) { return String.format("%0" + (2 * b.length) + "x", new BigInteger(1, b)); }

    private static List<?> hex1(P1[] p) { List<String> o = new ArrayList<>(); for (P1 x : p) o.add(hex(x.compress())); return o; }

    private static List<?> hex2(P2[] p) { List<String> o = new ArrayList<>(); for (P2 x : p) o.add(hex(x.compress())); return o; }

    @Test void matchesPyEcc() throws Exception {
        Map<String, Object> doc = m(Json.parseLenient(Files.readString(Path.of("test-data/fame-pyecc/fame-pyecc.json"))));
        for (Object co : (List<?>) doc.get("cases")) {
            Map<String, Object> c = m(co);
            String name = (String) c.get("name");
            AbePolicy.Result n = AbePolicy.normalize(c.get("policy"));
            assertNotNull(n.tree, name);
            List<String> attrs = new ArrayList<>();
            for (Object x : (List<?>) c.get("attrs")) attrs.add((String) x);
            Map<String, Object> s = m(c.get("scalars"));
            Fame.Master ms = Fame.setup(scalars(s.get("a")), scalars(s.get("b")), scalars(s.get("d")));
            Fame.Key key = Fame.keygen(ms.msk, attrs, scalars(s.get("r")), List.of(scalars(s.get("sigma"))), unhex(s.get("sigmaPrime")));
            Fame.Encapsulation e = Fame.encrypt(ms.mpk, n.tree, scalars(s.get("s")));
            assertEquals(c.get("h").toString(), List.of(hex(ms.mpk.h1.compress()), hex(ms.mpk.h2.compress())).toString(), name + " h");
            assertEquals(c.get("mskg").toString(), hex1(ms.msk.g).toString(), name + " mskg");
            assertEquals(c.get("k0").toString(), hex2(key.k0).toString(), name + " k0");
            assertEquals(c.get("kp").toString(), hex1(key.kp).toString(), name + " kp");
            for (Map.Entry<String, Object> en : m(c.get("key")).entrySet()) assertEquals(en.getValue().toString(), hex1(key.attrs.get(en.getKey())).toString(), name + " key " + en.getKey());
            assertEquals(c.get("ct0").toString(), hex2(e.ct.ct0).toString(), name + " ct0");
            List<String> rows = new ArrayList<>();
            for (P1[] r : e.ct.rows) rows.add(hex1(r).toString());
            List<String> want = new ArrayList<>();
            for (Object r : (List<?>) c.get("rows")) want.add(r.toString());
            assertEquals(want, rows, name + " rows");
            // the reference decrypted these with the attribute set it was issued; so must the native
            byte[] dec = Fame.decrypt(key, n.tree, e.ct);
            if (AbePolicy.satisfies(n.tree, new HashSet<>(attrs))) assertArrayEquals(e.k, dec, name + " decrypt");
        }
    }
}
