package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link Mesh} (and the Merkle primitives it rests on): a differential test against the TS reference
 * (oracle tools/pca-audit/k05-oracles/mesh-oracle.mts -> test-data/k05-mesh.json.gz). verifyMeshProof compares the verdict
 * (ok, reason, hop: TS trace / root_principal / leaf are TS-only extras), checkHeadAdvance the exact reason (null = "" here),
 * the Merkle checks the exact boolean, effectiveAuthority every member (or the error).
 */
public class K05MeshDiffTest {

    static List<Map<String, Object>> cases() throws Exception {
        return K05Oracle.all("k05-mesh");
    }

    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cases()) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static Object arg(Map<String, Object> c, int i) { List<?> a = (List<?>) c.get("args"); return i < a.size() ? a.get(i) : null; }
    static String canon(Object v) { return Json.canonicalize(IntentJs.normalize(v)); }
    static void report(List<String> bad, int ran) {
        assertTrue(ran > 0, "no cases ran");
        assertTrue(bad.isEmpty(), bad.size() + "/" + ran + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(60, bad.size()))));
    }
    static void diff(List<String> bad, Map<String, Object> c, String want, String got) {
        if (!want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
    }

    @Test void verifyMeshProof() throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (Map<String, Object> c : of("verifyMeshProof")) {
            Map<?, ?> o = (Map<?, ?>) c.get("out");
            String want = Boolean.TRUE.equals(o.get("ok")) ? "ok" : o.get("reason") + "|" + (o.containsKey("hop") ? IntentJs.lng(o.get("hop")) : -1);
            String got;
            try {
                Mesh.Verdict v = Mesh.verifyMeshProof(arg(c, 0), arg(c, 1));
                got = v.ok ? "ok" : v.reason + "|" + v.hop;
            } catch (Throwable t) { got = "THROWS " + t; }
            diff(bad, c, want, got);
            ran++;
        }
        report(bad, ran);
    }

    @Test void checkHeadAdvance() throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (Map<String, Object> c : of("checkHeadAdvance")) {
            Object prev = arg(c, 0), next = arg(c, 1);
            String want = c.get("out") == null ? "" : (String) c.get("out");
            String got;
            try { got = Mesh.checkHeadAdvance(prev, next, arg(c, 2)); } catch (Throwable t) { got = "THROWS " + t; }
            diff(bad, c, want, String.valueOf(got));
            ran++;
        }
        report(bad, ran);
    }

    @Test void verifyLedgerConsistency() throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (Map<String, Object> c : of("verifyLedgerConsistency")) {
            String got;
            try { got = String.valueOf(Ledger.verifyLedgerConsistency(arg(c, 0), arg(c, 1), arg(c, 2))); } catch (Throwable t) { got = "THROWS " + t; }
            diff(bad, c, String.valueOf(c.get("out")), got);
            ran++;
        }
        report(bad, ran);
    }

    @Test void verifyNonMembership() throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (Map<String, Object> c : of("verifyNonMembership")) {
            Object root = arg(c, 0), id = arg(c, 2);
            String got;
            try {
                got = String.valueOf(RevocationStaleness.verifyNonMembership(root instanceof String ? (String) root : null, Ledger.map(arg(c, 1)),
                    id instanceof String ? (String) id : null));
            } catch (Throwable t) { got = "THROWS " + t; }
            diff(bad, c, String.valueOf(c.get("out")), got);
            ran++;
        }
        report(bad, ran);
    }

    @Test void effectiveAuthority() throws Exception {
        List<String> bad = new ArrayList<>();
        int ran = 0;
        for (Map<String, Object> c : of("effectiveAuthority")) {
            String got;
            try {
                Mesh.Auth e = Mesh.effective(arg(c, 0));
                Map<String, Object> m = new LinkedHashMap<>();
                if (e.err != null) m.put("error", e.err);
                else {
                    m.put("prefixes", e.prefixes);
                    if (e.hasAct) m.put("actions", e.actions);
                    if (e.hasAmount) m.put("maxAmount", e.maxAmount);
                    if (e.hasExp) m.put("expiresAt", e.expiresAt);
                    if (e.hasAud) m.put("audience", e.audience);
                    if (e.hasHops) m.put("maxHops", e.maxHops);
                }
                got = canon(m);
            } catch (Throwable t) { got = "THROWS " + t; }
            diff(bad, c, canon(c.get("out")), got);
            ran++;
        }
        report(bad, ran);
    }
}
