package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link ProvenanceGate} (build provenance as a K1 discharge): a differential test against the TS
 * reference (oracle tools/pca-audit/k05-oracles/provgate-oracle.mts -> test-data/k05-provgate.json.gz). Facts and policy
 * validators compare the EXACT reason (or null); the gate its verdict, level and every claim; RFC 9162 inclusion its
 * boolean (real and tampered proofs, 2^40-leaf trees, every shape limit); the leaf hash its bytes; the caveat builder its
 * canonical JSON. Byte arguments travel as base64url; inclusion index / size as JSON integers.
 */
public class K05ProvGateDiffTest {

    /** Parsed once per JVM (the mutation run executes this class once per mutant). */
    static List<Map<String, Object>> cases() throws Exception {
        return K05Oracle.all("k05-provgate");
    }

    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cases()) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static List<?> args(Map<String, Object> c) { return (List<?>) c.get("args"); }
    static boolean isThrows(Object o) { return o instanceof Map && ((Map<?, ?>) o).containsKey("$throws"); }
    static String canon(Object v) { return Json.canonicalize(IntentJs.normalize(v)); }
    static byte[] bytes(Object b64u) { return Base64.getUrlDecoder().decode((String) b64u); }

    interface Fn { Object apply(List<?> a) throws Exception; }

    /** Exact canonical JSON equality; a {@code {$throws}} out requires a throw. */
    void check(String fn, Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = of(fn);
        for (Map<String, Object> c : cs) {
            Object want = c.get("out");
            String w = isThrows(want) ? "THROWS" : canon(want);
            String got;
            try { got = canon(f.apply(args(c))); } catch (Throwable t) { got = isThrows(want) ? "THROWS" : "THROWS " + t; }
            if (!w.equals(got)) bad.add(c.get("name") + "\n  want: " + w + "\n  got:  " + got);
        }
        assertTrue(bad.isEmpty(), fn + ": " + bad.size() + "/" + cs.size() + " divergent case(s):\n" + String.join("\n", bad));
    }

    @Test void factsShape() throws Exception { check("provenanceFactsError", a -> ProvenanceGate.provenanceFactsError(a.get(0))); }
    @Test void policyShape() throws Exception { check("provenancePolicyError", a -> ProvenanceGate.provenancePolicyError(a.get(0))); }

    @Test void gate() throws Exception {
        check("provenanceGate", a -> {
            ProvenanceGate.GateResult r = ProvenanceGate.provenanceGate(a.get(0));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", r.ok);
            if (r.ok) {
                m.put("level", r.level);
                m.put("claims", r.claims);
            } else m.put("code", r.code);
            return m;
        });
    }

    @Test void inclusion() throws Exception {
        check("verifyRfc9162Inclusion", a -> {
            List<byte[]> proof = new ArrayList<>();
            for (Object p : (List<?>) a.get(3)) proof.add(bytes(p));
            return ProvenanceGate.verifyRfc9162Inclusion(bytes(a.get(0)), IntentJs.lng(a.get(1)), IntentJs.lng(a.get(2)), proof, bytes(a.get(4)));
        });
    }

    @Test void leafHash() throws Exception {
        check("rfc9162LeafHash", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("$bytes", Pca.b64(ProvenanceGate.rfc9162LeafHash(bytes(a.get(0)))));
            return m;
        });
    }

    @SuppressWarnings("unchecked")
    @Test void caveat() throws Exception {
        check("provenanceCaveat", a -> {
            Map<String, Object> o = IntentJs.obj(a.get(0));
            ProvenanceGate.CaveatOptions c = new ProvenanceGate.CaveatOptions();
            c.id = (String) o.get("id");
            c.issuer = (String) o.get("issuer");
            c.minLevel = IntentJs.lng(o.get("min_level"));
            c.sourceRepo = (String) o.get("source_repo");
            c.builderIds = (List<String>) o.get("builder_ids");
            c.oidcIssuer = (String) o.get("oidc_issuer");
            c.requireRuntime = (Boolean) o.get("require_runtime");
            c.bind = (String) o.get("bind");
            c.ttlMs = o.containsKey("ttl_ms") ? IntentJs.lng(o.get("ttl_ms")) : null;
            return ProvenanceGate.provenanceCaveat(c);
        });
    }
}
