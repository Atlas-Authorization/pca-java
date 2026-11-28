package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The public vendor-attestation functions against the reference corpus (ref-attest-vendors, 758 cases over 22 function names): constants, parsers, the PCK chain, the genuine
 * quote, the CRL / signed-JSON / PCS-collateral checks, the Azure runtime-data binding, the JWT parsers, the x5c chain checks, and the two JWKS fetchers over a scripted transport.
 * Every case is replayed. A text the reference takes from a library (OpenSSL "error:...", JSON.parse messages, the P-256 library's point errors, "URI malformed") is compared by
 * presence only: the native must refuse or fail with some text, and those cases are counted.
 */
class AttestVendorsRefDiffTest {
    static final String MODULE = "ref-attest-vendors";
    static final int TOTAL = 758;

    private static Map<String, Object> m(Object o) { return AttestRootsKit.m(o); }

    private static Object arg(List<?> a, int i) { return AttestRootsKit.arg(a, i); }

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    private static byte[] bytes(Object o) { return (byte[]) o; }

    private static String str(Object o) { return o instanceof String ? (String) o : null; }

    private static Double optNum(Object o) { return o == null ? null : dbl(o); }

    private static boolean lib(Object r) {
        if (!(r instanceof String)) return false;
        String s = (String) r;
        return AttestRootsKit.libText(s) || s.startsWith("Unexpected token") || s.startsWith("Unexpected end of JSON input") || s.startsWith("bad point:") || s.startsWith("invalid Point,") || s.equals("URI malformed");
    }

    /** The scripted transport: script[min(i, last)] answers the i-th request; every requested URL is logged. */
    private static AttestMaaKeys.Fetch scripted(List<?> script, List<Object> log) {
        int[] i = {0};
        return url -> {
            log.add(url);
            Map<String, Object> s = m(script.get(Math.min(i[0]++, script.size() - 1)));
            if (s.containsKey("$throws")) throw new RuntimeException((String) s.get("$throws"));
            Object body = s.get("body");
            byte[] b = m(body) != null && m(body).get("$text") instanceof String ? ((String) m(body).get("$text")).getBytes(StandardCharsets.UTF_8) : Json.canonicalize(body).getBytes(StandardCharsets.UTF_8);
            return new AttestMaaKeys.Response(s.get("status") == null ? 200 : (int) dbl(s.get("status")), null, null, b);
        };
    }

    private interface Fetcher { Map<String, Object> run(String issuer, AttestMaaKeys.Fetch f, Map<String, Object> opts) throws Exception; }

    private static Object fetch(List<?> x, Fetcher f) {
        Map<String, Object> sc = m(arg(x, 0));
        List<Object> log = new ArrayList<>();
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            out.put("jwks", f.run((String) sc.get("issuer"), scripted((List<?>) sc.get("script"), log), m(sc.get("opts"))));
            out.put("ok", true);
        } catch (Exception e) {
            out.remove("jwks");
            out.put("ok", false);
            out.put("error", String.valueOf(e.getMessage()));
        }
        out.put("requests", log);
        return out;
    }

    private static Map<String, OracleCases.Fn> table() {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> AttestVendorsApi.constants());
        f.put("toHex", x -> AttestCommon.toHexLower(bytes(arg(x, 0))));
        f.put("pemToDer", x -> AttestVendorsApi.pemToDer((String) arg(x, 0)));
        f.put("ecdsaP256PublicKey", x -> Issue.obj("point", AttestVendorsApi.ecdsaP256PublicKey(bytes(arg(x, 0)))));
        f.put("parseDcapTdReport", x -> AttestVendorsApi.parseDcapTdReport(bytes(arg(x, 0))));
        f.put("parseDcapQuote", x -> AttestVendorsApi.parseDcapQuote(bytes(arg(x, 0))));
        f.put("extractPckFmspcAndTcb", x -> AttestVendorsApi.extractPckFmspcAndTcb(bytes(arg(x, 0))));
        f.put("verifyIntelPckChainX509", x -> {
            Map<String, Object> a = m(arg(x, 0));
            return AttestVendorsApi.verifyIntelPckChainX509((String) a.get("pckChainPem"), str(a.get("trustAnchorRootCaSpkiSha256")), (long) dbl(a.get("nowMs")));
        });
        f.put("verifyGenuineTdxQuote", x -> {
            Map<String, Object> a = m(arg(x, 0));
            return AttestVendorsApi.verifyGenuineTdxQuote(bytes(a.get("quote")), str(a.get("trustAnchorRootCaSpkiSha256")), (long) dbl(a.get("nowMs")), m(a.get("expected")), m(a.get("policy")));
        });
        f.put("verifyCrl", x -> AttestVendorsApi.verifyCrl(bytes(arg(x, 0)), bytes(m(arg(x, 1)).get("spkiDer")), (long) dbl(arg(x, 2))));
        f.put("serialIsRevoked", x -> {
            Set<String> set = new HashSet<>();
            for (Object o : (List<?>) arg(x, 0)) set.add((String) o);
            return AttestVendorsApi.serialIsRevoked(set, (String) arg(x, 1));
        });
        f.put("verifySignedJson", x -> AttestVendorsApi.verifySignedJson((String) arg(x, 0), (String) arg(x, 1), bytes(m(arg(x, 2)).get("spkiDer"))));
        f.put("decodeIssuerChainHeader", x -> AttestVendorsApi.decodeIssuerChainHeader((String) arg(x, 0)));
        f.put("verifyIntelTdxCollateral", x -> {
            Map<String, Object> a = m(arg(x, 0));
            return AttestVendorsApi.verifyIntelTdxCollateral(bytes(a.get("quote")), m(a.get("collateral")), (long) dbl(a.get("nowMs")), m(a.get("policy")), str(a.get("trustAnchorRootCaSpkiSha256")),
                Boolean.TRUE.equals(a.get("allowDebug")));
        });
        f.put("checkAzureRuntimeDataBinding", x -> AttestVendorsApi.checkAzureRuntimeDataBinding(bytes(arg(x, 0)), bytes(arg(x, 1)), m(arg(x, 2))));
        f.put("parseMaaJwt", x -> AttestVendorsApi.jwtRecord(AttestVendorsApi.parseMaaJwt((String) arg(x, 0))));
        f.put("parseGcpCsJwt", x -> AttestVendorsApi.jwtRecord(AttestVendorsApi.parseGcpCsJwt((String) arg(x, 0))));
        f.put("verifyX5cChain", x -> AttestVendorsApi.verifyX5cChain(arg(x, 0), m(arg(x, 1)), (long) dbl(m(arg(x, 2)).get("nowMs")), optNum(m(arg(x, 2)).get("clockSkewMs"))));
        f.put("verifyJwkX5cChain", x -> AttestVendorsApi.verifyJwkX5cChain(arg(x, 0), m(arg(x, 1)), (long) dbl(m(arg(x, 2)).get("nowMs")), dbl(m(arg(x, 2)).get("skewMs"))));
        f.put("teeTypeOfHwModel", x -> AttestVendorsApi.teeTypeOfHwModel((String) arg(x, 0)));
        f.put("fetchMaaJwks", x -> fetch(x, (iss, ft, o) -> AttestVendorsApi.fetchMaaJwks(iss, ft, o == null ? null : str(o.get("certsPath")))));
        f.put("fetchGcpConfidentialSpaceJwks", x -> fetch(x, (iss, ft, o) -> AttestVendorsApi.fetchGcpConfidentialSpaceJwks(iss, ft, o == null ? null : str(o.get("jwksUri")))));
        return f;
    }

    /** Where the reference text is library text and the native also gave a text, both become one marker (presence only); counts the cases it applies to. */
    @SuppressWarnings("unchecked")
    private static Object align(Object want, Object got, int[] libs) {
        if (lib(want) && got instanceof String && !((String) got).isEmpty()) {
            libs[0]++;
            return "<lib>";
        }
        if (want instanceof List && got instanceof List && ((List<?>) want).size() == ((List<?>) got).size()) {
            List<Object> w = (List<Object>) want, g = (List<Object>) got;
            for (int i = 0; i < w.size(); i++) {
                Object r = align(w.get(i), g.get(i), libs);
                if ("<lib>".equals(r) && !(w.get(i) instanceof Map)) { w.set(i, r); g.set(i, r); }
            }
        } else if (want instanceof Map && got instanceof Map) {
            Map<String, Object> w = (Map<String, Object>) want, g = (Map<String, Object>) got;
            for (Map.Entry<String, Object> e : w.entrySet()) {
                if (!g.containsKey(e.getKey())) continue;
                Object r = align(e.getValue(), g.get(e.getKey()), libs);
                if ("<lib>".equals(r) && !(e.getValue() instanceof Map)) { e.setValue(r); g.put(e.getKey(), r); }
            }
        }
        return null;
    }

    private static String sameThrow(String name, String fn, String want, Throwable got, int[] libs) {
        if (got == null) return name + "\n  want: throw " + want + "\n  got:  no throw";
        if (lib(want) || want.contains(": Unexpected token") || want.contains(": Unexpected end of JSON input")) {
            libs[0]++;
            int i = want.indexOf("Unexpected");
            String pre = i > 0 ? want.substring(0, i) : "";
            String g = String.valueOf(got.getMessage());
            return g.startsWith(pre) && !g.isEmpty() ? null : name + "\n  want: throw " + want + "\n  got:  " + g;
        }
        String g = String.valueOf(got.getMessage());
        return g.equals(want) ? null : name + "\n  want: throw " + want + "\n  got:  throw " + g;
    }

    @SuppressWarnings("unchecked")
    @Test void everyFunction() throws Exception {
        Map<String, Object> blobs = AttestRootsKit.blobs(MODULE);
        Map<String, OracleCases.Fn> tbl = table();
        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size(), "case total");
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(tbl.keySet()), fns, "every fn of the corpus is replayed");
        List<String> bad = new ArrayList<>();
        int replayed = 0;
        int[] libs = {0};
        for (Map<String, Object> raw : all) {
            Map<String, Object> c = AttestRootsKit.hydrated(raw, blobs);
            replayed++;
            String fn = (String) c.get("fn"), name = String.valueOf(c.get("name"));
            Object want = c.get("out");
            Object got = null;
            Throwable err = null;
            try {
                got = tbl.get(fn).apply((List<?>) AttestRootsKit.dec(c.get("args")));
            } catch (Throwable t) {
                err = t;
            }
            if (m(want) != null && m(want).containsKey("$throws")) {
                String d = sameThrow(name, fn, (String) m(want).get("$throws"), err, libs);
                if (d != null) bad.add(d);
                continue;
            }
            if (err != null) { bad.add(name + "\n  want: " + Json.canonicalize(want) + "\n  got:  THROWS " + err); continue; }
            Object norm = IntentJs.normalize(OracleCases.toJson(got));
            Object w = want;
            Object top = align(w, norm, libs);
            if ("<lib>".equals(top)) { w = top; norm = top; }
            if (!IntentJs.jsonEquals(w, norm)) {
                String g;
                try { g = Json.canonicalize(norm); } catch (RuntimeException e) { g = String.valueOf(norm); }
                String ws = Json.canonicalize(w);
                bad.add(name + "\n  want: " + (ws.length() > 1500 ? ws.substring(0, 1500) + "..." : ws) + "\n  got:  " + (g.length() > 1500 ? g.substring(0, 1500) + "..." : g));
            }
        }
        assertEquals(TOTAL, replayed, "every case was replayed");
        assertTrue(libs[0] > 0, "the library-text cases are counted");
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) (" + libs[0] + " compared by presence as library text):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
