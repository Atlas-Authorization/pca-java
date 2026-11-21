package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The AMD SEV-SNP evidence helpers against the reference corpus (ref-sevsnp-helpers, 248 cases): the report parser, the P-384 key and
 * signature helpers, the report signature, the VCEK certificate helpers and binding, the policy gate, the default identity derivation
 * and the KDS fetch over an injected transport. The chain and the genuine-report check run over the real Milan and Genoa chains of the
 * evidence corpus.
 */
class SevSnpHelpersRefDiffTest {
    static final String MODULE = "ref-sevsnp-helpers";
    static final int TOTAL = 248;
    static final String MALFORMED = "VCEK extensions malformed:";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    /** {"$bytes"} as bytes, {"$bigint"} as a BigInteger, {"$num"} as that double, throughout a value. */
    @SuppressWarnings("unchecked")
    private static Object dec(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(dec(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$bytes") instanceof String) return Base64.getUrlDecoder().decode((String) map.get("$bytes"));
        if (map.size() == 1 && map.get("$bigint") instanceof String) return new BigInteger((String) map.get("$bigint"));
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), dec(e.getValue()));
        return out;
    }

    private static byte[] bytes(List<?> x, int i) { return (byte[]) dec(arg(x, i)); }

    private static Object big(BigInteger v) { return Issue.obj("$bigint", v.toString()); }

    private static Object ver(HardwareSevSnp.FirmwareVersion v) { return Issue.obj("major", v.major, "minor", v.minor, "build", v.build); }

    private static Object parsed(byte[] b) {
        HardwareSevSnp.ParsedReport r = HardwareSevSnp.parseSevSnpReport(b);
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("version", r.version);
        o.put("guest_svn", r.guestSvn);
        o.put("policy", big(r.policy));
        o.put("family_id", r.familyId);
        o.put("image_id", r.imageId);
        o.put("vmpl", r.vmpl);
        o.put("signature_algo", r.signatureAlgo);
        o.put("current_tcb", big(r.currentTcb));
        o.put("platform_info", big(r.platformInfo));
        o.put("report_data", r.reportData);
        o.put("measurement", r.measurement);
        o.put("host_data", r.hostData);
        o.put("id_key_digest", r.idKeyDigest);
        o.put("author_key_digest", r.authorKeyDigest);
        o.put("report_id", r.reportId);
        o.put("report_id_ma", r.reportIdMa);
        o.put("reported_tcb", big(r.reportedTcb));
        o.put("cpuid_fam_id", r.cpuidFamId);
        o.put("cpuid_mod_id", r.cpuidModId);
        o.put("cpuid_step", r.cpuidStep);
        o.put("chip_id", r.chipId);
        o.put("committed_tcb", big(r.committedTcb));
        o.put("current_version", ver(r.currentVersion));
        o.put("committed_version", ver(r.committedVersion));
        o.put("launch_tcb", big(r.launchTcb));
        o.put("launch_mit_vector", big(r.launchMitVector));
        o.put("current_mit_vector", big(r.currentMitVector));
        o.put("signature", Issue.obj("r", r.signatureR, "s", r.signatureS));
        o.put("signed_len", r.signed.length);
        o.put("signed_sha256", AttestCommon.toHexLower(AttestCommon.sha256Sum(r.signed)));
        o.put("raw_len", r.raw.length);
        return o;
    }

    private static Object fetchVcek(List<?> x) throws Exception {
        Map<String, Object> op = m(dec(arg(x, 2)));
        String[] seen = new String[1];
        HardwareSevSnp.Fetch fetch = Boolean.TRUE.equals(op.get("noFetch")) ? null : url -> {
            seen[0] = url;
            return new HardwareSevSnp.Response(((Number) IntentJs.num(op.get("status"))).intValue(), (byte[]) op.get("body"));
        };
        byte[] got = HardwareSevSnp.fetchVcekFromKds(bytes(x, 0), (BigInteger) dec(arg(x, 1)), (String) op.get("product"), (String) op.get("baseUrl"), fetch);
        return Issue.obj("url", seen[0], "bytes", got);
    }

    /** A reason that starts with the malformed-extensions prefix keeps only the prefix (the text after it is the reference's own). */
    private static Object cut(Object v) { return v instanceof String && ((String) v).startsWith(MALFORMED) ? MALFORMED : v; }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384", HardwareSevSnp.SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384,
            "SEV_SNP_POLICY_DEBUG_BIT", big(HardwareSevSnp.SEV_SNP_POLICY_DEBUG_BIT), "AMD_MILAN_ARK_SPKI_SHA384", HardwareSevSnp.AMD_MILAN_ARK_SPKI_SHA384));
        f.put("toHex", x -> HardwareSevSnp.toHex(bytes(x, 0)));
        f.put("splitPemCertificates", x -> HardwareSevSnp.splitPemCertificates((String) arg(x, 0)));
        f.put("parseReport", x -> parsed(bytes(x, 0)));
        f.put("ecdsaP384PublicKey", x -> Issue.obj("point", HardwareSevSnp.ecdsaP384PublicKey(bytes(x, 0)).point));
        f.put("signatureToCompact", x -> {
            Map<String, Object> s = m(dec(arg(x, 0)));
            return HardwareSevSnp.sevSnpSignatureToCompact((byte[]) s.get("r"), (byte[]) s.get("s"));
        });
        f.put("verifyReportSignature", x -> HardwareSevSnp.verifySevSnpReportSignature(HardwareSevSnp.parseSevSnpReport(bytes(x, 0)), HardwareSevSnp.ecdsaP384PublicKey(bytes(x, 1))));
        f.put("checkPolicy", x -> HardwareSevSnp.checkSevSnpPolicy(HardwareSevSnp.parseSevSnpReport(bytes(x, 0)), m(dec(arg(x, 1)))));
        f.put("deriveIdentity", x -> HardwareSevSnp.makeDefaultDeriveIdentity(Boolean.TRUE.equals(arg(x, 1))).apply(HardwareSevSnp.parseSevSnpReport(bytes(x, 0))));
        f.put("fetchVcek", SevSnpHelpersRefDiffTest::fetchVcek);
        f.put("extractTbsCertificate", x -> HardwareSevSnp.extractTbsCertificate(bytes(x, 0)));
        f.put("extractVcekPublicKey", x -> {
            HardwareSevSnp.VcekKey k = HardwareSevSnp.extractVcekPublicKey(bytes(x, 0));
            return Issue.obj("point", k.key.point, "tbs", k.tbs);
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>(), handled = new TreeSet<>(f.keySet());
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        handled.add("checkVcekReportBinding"); // replayed below
        assertEquals(handled, fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }

    @Test void vcekBindingEveryCase() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(MODULE, "checkVcekReportBinding")) {
            String d = OracleCases.diff(c, cut(c.get("out")), x -> cut(HardwareSevSnp.checkVcekReportBinding(bytes(x, 0), HardwareSevSnp.parseSevSnpReport(bytes(x, 1)))));
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad));
    }
}
