package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

/** Replays the x509_vectors rows of the shared attestation evidence vectors against the strict readers of AttestDer. */
public class AttestX509VectorsTest {
    private static Map<String, Object> okv(Object v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("value", v);
        return m;
    }

    private static Map<String, Object> bad(AttestException e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("error", e.getMessage());
        return m;
    }

    private static byte[] b64(Object v) {
        assertTrue(v instanceof String, "not a base64 string: " + v);
        return AttestCommon.nodeB64((String) v);
    }

    private static List<Object> extList(AttestDer.ExtTable t) {
        List<Object> out = new ArrayList<>();
        for (String oid : t.oids) {
            AttestDer.CertExt e = t.m.get(oid);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("oid", oid);
            m.put("critical", e.critical);
            m.put("value", AttestCommon.toHexLower(e.value));
            out.add(m);
        }
        return out;
    }

    private static Object instant(AttestDer.DerInstant i) { return i.ok ? (Object) Long.valueOf(i.ms) : null; }

    @SuppressWarnings("unchecked")
    static Map<String, Object> run(String fn, Map<String, Object> in) {
        try {
            switch (fn) {
                case "read_cert_role_info": {
                    AttestDer.CertRoleInfo info = AttestDer.readCertRoleInfo(b64(in.get("cert")));
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("hasBasicConstraints", info.hasBasicConstraints);
                    m.put("ca", info.ca);
                    m.put("hasKeyUsage", info.hasKeyUsage);
                    m.put("keyCertSign", info.keyCertSign);
                    if (info.pathLen >= 0) m.put("pathLen", (long) info.pathLen);
                    return okv(m);
                }
                case "parse_cert_extensions":
                    return okv(extList(AttestDer.parseCertExtensions(b64(in.get("cert")))));
                case "parse_tbs_extensions":
                    return okv(extList(AttestDer.parseTbsExtensions(b64(in.get("tbs")))));
                case "tbs_of_certificate":
                    return okv(Base64.getEncoder().encodeToString(AttestDer.tbsOfCertificate(b64(in.get("cert")))));
                case "unrecognised_critical_extension": {
                    Set<String> rec = null;
                    if (in.get("recognised") instanceof List) {
                        rec = new HashSet<>();
                        for (Object x : (List<Object>) in.get("recognised")) rec.add((String) x);
                    }
                    return okv(AttestDer.unrecognisedCriticalExtension(b64(in.get("cert")), rec));
                }
                case "check_chain_roles": {
                    List<byte[]> chain = new ArrayList<>();
                    for (Object c : (List<Object>) in.get("chain")) chain.add(b64(c));
                    String why = AttestDer.checkChainRoles(chain);
                    return okv(why.isEmpty() ? null : why);
                }
                case "der_validity_ms": {
                    AttestDer.DerInstant[] v = AttestDer.derValidity(b64(in.get("cert")));
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("from", instant(v[0]));
                    m.put("to", instant(v[1]));
                    return okv(m);
                }
                case "parse_der_time": {
                    Double tag = AttestCommon.asFinite(in.get("tag"));
                    return okv(instant(AttestDer.parseDerTime(tag == null ? 0 : tag.intValue(), (String) in.get("text"))));
                }
                default:
                    throw new IllegalStateException("unknown x509 function " + fn);
            }
        } catch (AttestException e) {
            return bad(e);
        }
    }

    @SuppressWarnings("unchecked")
    @Test void x509Rows() {
        List<Map<String, Object>> rows = AttestVectors.rows("x509_vectors");
        assertTrue(rows.size() >= 90, "only " + rows.size() + " x509 vectors");
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            Map<String, Object> got = run((String) row.get("fn"), (Map<String, Object>) row.get("input"));
            String g = AttestVectors.canon(got);
            String w = AttestVectors.canon(row.get("expect"));
            if (!g.equals(w)) failures.add(row.get("id") + ": got " + g + " want " + w);
        }
        assertEquals(new ArrayList<String>(), failures.size() > 10 ? failures.subList(0, 10) : failures);
    }
}
