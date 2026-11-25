package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The NVIDIA GPU-CC modules against the reference corpora: ref-attest-nvidia (467 cases: SPDM report parse, device chain, report signature, PCA
 * challenge, RIM ids and the golden comparison, CRL revocation, the fetch helpers, the OCSP request build, response verification and per-chain
 * policy, the ASN.1 time check) and ref-attest-nvidia-rim (163 cases: RIM XMLDSig verification and the collateral hook). Library-text
 * reasons (OpenSSL, the ASN.1 library, "OCSP response rejected:") are compared by presence only.
 */
class AttestNvidiaRefDiffTest {
    static final String MODULE = "ref-attest-nvidia";
    static final int TOTAL = 467;
    static final String RIM_MODULE = "ref-attest-nvidia-rim";
    static final int RIM_TOTAL = 163;

    private static Map<String, Object> m(Object o) { return AttestRootsKit.m(o); }

    private static Object arg(List<?> a, int i) { return AttestRootsKit.arg(a, i); }

    private static Object dec(Object o) { return AttestRootsKit.dec(o); }

    private static long lng(Object o) { return (long) IntentJs.num(o).doubleValue(); }

    @SuppressWarnings("unchecked")
    private static List<byte[]> bytesList(Object o) {
        List<byte[]> out = new ArrayList<>();
        if (o instanceof List) for (Object x : (List<Object>) o) out.add((byte[]) dec(x));
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) for (Object x : (List<Object>) o) out.add((String) x);
        return out;
    }

    /** The scripted transport: one answer, every request logged as {url, method, contentType[, bodyBytes]}. */
    private static HardwareSevSnp.Response answer(Map<String, Object> r) throws Exception {
        if (r.get("$throws") != null) throw new RuntimeException((String) r.get("$throws"));
        Object bb = r.get("bodyBytes");
        byte[] body = bb != null ? (byte[]) dec(bb) : Json.canonicalize(r.get("body")).getBytes(StandardCharsets.UTF_8);
        return new HardwareSevSnp.Response(r.get("status") == null ? 200 : (int) lng(r.get("status")), body);
    }

    private static Object fetched(Map<String, Object> sc, List<Object> log, boolean value, java.util.concurrent.Callable<Object> call) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            out.put("ok", true);
            Object v = call.call();
            if (value) out.put("value", v);
            else out.putAll(m(v));
        } catch (Exception e) {
            out.clear();
            out.put("ok", false);
            out.put("error", e.getMessage());
        }
        out.put("requests", log);
        return out;
    }

    private static Object fetchRim(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        List<Object> log = new ArrayList<>();
        Map<String, Object> r = m(sc.get("response"));
        return fetched(sc, log, true, () -> AttestNvidiaApi.fetchNvidiaRim((String) sc.get("id"), url -> {
            log.add(Issue.obj("url", url, "method", "GET", "contentType", null));
            return answer(r);
        }, (String) sc.get("baseUrl")));
    }

    private static Object fetchCrl(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        List<Object> log = new ArrayList<>();
        Map<String, Object> r = m(sc.get("response"));
        return fetched(sc, log, true, () -> AttestNvidiaApi.fetchNvidiaCrl((String) sc.get("url"), url -> {
            log.add(Issue.obj("url", url, "method", "GET", "contentType", null));
            return answer(r);
        }));
    }

    private static Object fetchOcsp(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        List<Object> log = new ArrayList<>();
        Map<String, Object> r = m(sc.get("response")), o = m(sc.get("opts"));
        return fetched(sc, log, false, () -> AttestNvidiaApi.fetchNvidiaOcsp((String) sc.get("certPem"), (String) sc.get("issuerPem"), (url, ct, body) -> {
            log.add(Issue.obj("url", url, "method", "POST", "contentType", ct, "bodyBytes", body.length));
            return answer(r);
        }, o == null ? null : (String) o.get("url"), o == null || o.get("nonce") == null ? null : (byte[]) dec(o.get("nonce"))));
    }

    private static Object checkRevocation(List<?> x) {
        Object req = arg(x, 4);
        return AttestNvidiaApi.checkNvidiaChainRevocation((String) arg(x, 0), bytesList(arg(x, 1)), lng(arg(x, 2)), strings(arg(x, 3)), req);
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("NVIDIA_SPDM_SUITE", AttestNvidiaApi.NVIDIA_SPDM_SUITE, "NVIDIA_OPAQUE", new LinkedHashMap<String, Object>(AttestNvidiaApi.NVIDIA_OPAQUE),
            "NVIDIA_RIM_BASE_URL", AttestNvidiaApi.NVIDIA_RIM_BASE_URL, "NVIDIA_GH100_CRL_URLS", new ArrayList<Object>(AttestNvidiaApi.NVIDIA_GH100_CRL_URLS),
            "NVIDIA_GB100_CRL_URLS", new ArrayList<Object>(AttestNvidiaApi.NVIDIA_GB100_CRL_URLS), "NVIDIA_OCSP_URL", AttestNvidiaApi.NVIDIA_OCSP_URL,
            "NVIDIA_OCSP_DEFAULT_MAX_AGE_MS", AttestNvidiaApi.NVIDIA_OCSP_DEFAULT_MAX_AGE_MS));
        f.put("parseReport", x -> AttestNvidiaApi.parseNvidiaSpdmEvidence((byte[]) dec(arg(x, 0))));
        f.put("formatVbiosVersion", x -> AttestNvidiaApi.formatVbiosVersion((byte[]) dec(arg(x, 0))));
        f.put("spkiSha256Hex", x -> AttestNvidiaApi.spkiSha256Hex((String) arg(x, 0)));
        f.put("parsePemChain", x -> AttestNvidiaApi.parsePemChain((String) arg(x, 0)));
        f.put("verifyDeviceChain", x -> AttestNvidiaApi.verifyNvidiaDeviceChain((String) arg(x, 0), strings(arg(x, 1)), lng(arg(x, 2))));
        f.put("verifySpdmSignature", x -> AttestNvidiaApi.verifyNvidiaSpdmSignature((byte[]) dec(arg(x, 0)), (String) arg(x, 1)));
        f.put("spdmChallenge", x -> AttestNvidiaApi.nvidiaSpdmChallenge(AttestVectors.bindingOf(arg(x, 0))));
        f.put("rimIds", x -> AttestNvidiaApi.nvidiaRimIdsForReport((byte[]) dec(arg(x, 0))));
        f.put("compareReport", x -> AttestNvidiaApi.compareReportToRims((byte[]) dec(arg(x, 0)), m(arg(x, 1)), m(arg(x, 2))));
        f.put("checkRevocation", AttestNvidiaRefDiffTest::checkRevocation);
        f.put("fetchRim", AttestNvidiaRefDiffTest::fetchRim);
        f.put("fetchCrl", AttestNvidiaRefDiffTest::fetchCrl);
        f.put("ocspRequest", x -> AttestNvidiaApi.buildNvidiaOcspRequest((String) arg(x, 0), (String) arg(x, 1), m(dec(arg(x, 2)))));
        f.put("ocspUrls", x -> new ArrayList<Object>(AttestNvidiaApi.nvidiaCertOcspUrls((String) arg(x, 0))));
        f.put("ocspVerify", x -> AttestNvidiaApi.verifyNvidiaOcspResponse((byte[]) dec(arg(x, 0)), m(dec(arg(x, 1)))));
        f.put("ocspChain", x -> AttestNvidiaApi.checkNvidiaChainOcsp((String) arg(x, 0), bytesList(arg(x, 1)), lng(arg(x, 2)), m(dec(arg(x, 3)))));
        f.put("fetchOcsp", AttestNvidiaRefDiffTest::fetchOcsp);
        f.put("asn1TimesWellFormed", x -> AttestNvidiaApi.allAsn1TimesWellFormed((byte[]) dec(arg(x, 0))));
        AttestRootsKit.replay(MODULE, TOTAL, f, null);
    }

    @SuppressWarnings("unchecked")
    private static Object bundleOf(Object b) {
        Map<String, Object> bm = m(b);
        if (bm == null) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : bm.entrySet()) {
            if (e.getValue() instanceof List) {
                List<Object> l = new ArrayList<>();
                for (Object y : (List<Object>) e.getValue()) l.add(m(y) != null && m(y).get("$bytes") instanceof String ? m(y).get("$bytes") : y); // a DER as its base64url text
                out.put(e.getKey(), l);
            } else out.put(e.getKey(), e.getValue());
        }
        return out;
    }

    private static Object collateralHook(List<?> x) {
        Map<String, Object> sc = m(arg(x, 0));
        String why = AttestNvidiaApi.nvidiaCollateralHook(m(sc.get("opts")), m(bundleOf(sc.get("bundle"))), (byte[]) dec(sc.get("evidence")), (String) sc.get("chainPem"), lng(sc.get("nowMs")));
        return Issue.obj("value", why);
    }

    @Test void rimAndCollateralHook() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("verifyRim", x -> {
            Map<String, Object> o = m(arg(x, 1));
            return AttestNvidiaApi.verifyNvidiaRim(arg(x, 0) instanceof String ? (String) arg(x, 0) : null, strings(o.get("rimRootSpkiSha256")), lng(o.get("nowMs")));
        });
        f.put("collateralHook", AttestNvidiaRefDiffTest::collateralHook);
        AttestRootsKit.replay(RIM_MODULE, RIM_TOTAL, f, null);
    }
}
