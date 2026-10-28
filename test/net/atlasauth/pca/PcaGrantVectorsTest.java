package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The {@code pca_grant} authorization-details corpus (pca-grant-vectors.json). A missing file or a shrunken corpus FAILS. */
public class PcaGrantVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("pca-grant-vectors.json");

    @SuppressWarnings("unchecked")
    static List<Object> list(String k) { return (List<Object>) DOC.get(k); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<String> strs(Object o) { return new ArrayList<>((List<String>) (List<?>) o); }

    @Test void digests() {
        for (Object x : list("digest")) assertEquals(m(x).get("digest"), PcaGrant.chainDigest(strs(m(x).get("ids"))));
    }

    @Test void details() {
        assertEquals(true, list("detail").size() >= 40);
        for (Object x : list("detail")) {
            Map<String, Object> v = m(x);
            String code = PcaGrant.validate(v.get("input"));
            Map<String, Object> exp = m(v.get("expect"));
            assertEquals(exp.get("ok"), code == null, v.get("name") + ": ok");
            if (code != null) assertEquals(exp.get("code"), code, v.get("name") + ": code");
        }
    }

    @Test void arrays() {
        for (Object x : list("array")) {
            Map<String, Object> v = m(x);
            PcaGrant.Result r = PcaGrant.parse(v.get("input"));
            Map<String, Object> exp = m(v.get("expect"));
            assertEquals(exp.get("ok"), r.code == null, v.get("name") + ": ok");
            if (r.code == null) assertEquals(Json.asLong(exp.get("count")), r.details.size(), v.get("name") + ": count");
            else assertEquals(exp.get("code"), r.code, v.get("name") + ": code");
        }
    }

    @SuppressWarnings("unchecked")
    @Test void presentations() {
        for (Object x : list("presentation")) {
            Map<String, Object> v = m(x);
            Map<String, Object> p = m(v.get("presented"));
            List<Map<String, Object>> details = new ArrayList<>();
            for (Object d : (List<Object>) v.get("details")) details.add(m(d));
            PcaGrant.Result r = PcaGrant.check(details, (String) p.get("resource"), strs(p.get("chain_ids")), (Boolean) p.get("proof_verified"));
            Map<String, Object> exp = m(v.get("expect"));
            assertEquals(exp.get("allow"), r.code == null, v.get("name") + ": allow");
            if (r.code == null) assertEquals(Json.asLong(exp.get("index")), (long) r.index, v.get("name") + ": index");
            else assertEquals(exp.get("code"), r.code, v.get("name") + ": code");
        }
    }
}
