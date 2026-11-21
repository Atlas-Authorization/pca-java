package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The build-provenance corpus (provenance-vectors.json, track K9). A missing file FAILS. */
public class ProvenanceVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("provenance-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> rows(String name) { return (List<Object>) m(DOC.get("primitives")).get(name); }

    static byte[] unhex(Object h) {
        String s = (String) h;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static void same(Object want, Object got, String name) {
        assertTrue(IntentJs.jsonEquals(want, got), name + ": want " + want + ", got " + got);
    }

    @Test void merkleInclusion() {
        List<Object> rs = rows("merkle_inclusion");
        assertEquals(44, rs.size());
        for (Object x : rs) {
            Map<String, Object> v = m(x), in = m(v.get("input"));
            List<byte[]> proof = new ArrayList<>();
            for (Object h : (List<?>) in.get("proof_hex")) proof.add(unhex(h));
            boolean ok = ProvenanceGate.verifyRfc9162Inclusion(ProvenanceGate.rfc9162LeafHash(unhex(in.get("leaf_hex"))),
                Json.asLong(in.get("index")), Json.asLong(in.get("size")), proof, unhex(in.get("root_hex")));
            same(v.get("expect"), Map.of("ok", ok), (String) v.get("name"));
        }
    }

    @Test void gate() {
        List<Object> rs = rows("gate");
        assertEquals(45, rs.size());
        for (Object x : rs) {
            Map<String, Object> v = m(x);
            ProvenanceGate.GateResult r = ProvenanceGate.provenanceGate(v.get("input"));
            Map<String, Object> got = new LinkedHashMap<>();
            got.put("ok", r.ok);
            if (r.ok) {
                got.put("level", r.level);
                got.put("claims", r.claims);
            } else got.put("code", r.code);
            same(v.get("expect"), got, (String) v.get("name"));
        }
    }

    @Test void modelPath() {
        List<Object> rs = rows("model_path");
        assertEquals(7, rs.size());
        for (Object x : rs) {
            Map<String, Object> v = m(x);
            same(v.get("expect"), Map.of("model", Decision.isModelDerivedPath(m(v.get("input")).get("path"), List.of())), (String) v.get("name"));
        }
    }

    @Test void caveatDefaultsAndOrder() {
        ProvenanceGate.CaveatOptions o = new ProvenanceGate.CaveatOptions();
        o.issuer = "slsa";
        o.minLevel = 3;
        o.sourceRepo = "r";
        Map<String, Object> c = ProvenanceGate.provenanceCaveat(o);
        same(Json.parseLenient("{\"type\":\"needs_discharge\",\"id\":\"provenance\",\"issuer\":\"slsa\",\"issuer_class\":\"artifact\",\"bind\":\"action\",\"ttl_ms\":300000,"
            + "\"require\":[{\"claim\":\"slsa_level\",\"op\":\"gte\",\"value\":3},{\"claim\":\"source_repo\",\"op\":\"eq\",\"value\":\"r\"},{\"claim\":\"runtime_bound\",\"op\":\"eq\",\"value\":true}]}"), c, "defaults");
        assertNull(CaveatLang.needsDischargeError(c));
        o.id = "prov";
        o.sourceRepo = null;
        o.minLevel = 2;
        o.builderIds = List.of("b");
        o.oidcIssuer = "i";
        o.requireRuntime = false;
        o.bind = "chain_hop";
        o.ttlMs = 1000L;
        Map<String, Object> all = ProvenanceGate.provenanceCaveat(o);
        same(Json.parseLenient("[{\"claim\":\"slsa_level\",\"op\":\"gte\",\"value\":2},{\"claim\":\"builder_id\",\"op\":\"in\",\"value\":[\"b\"]},{\"claim\":\"oidc_issuer\",\"op\":\"eq\",\"value\":\"i\"}]"), all.get("require"), "require");
        assertEquals(List.of("prov", "chain_hop", 1000L), List.of(all.get("id"), all.get("bind"), all.get("ttl_ms")));
    }
}
