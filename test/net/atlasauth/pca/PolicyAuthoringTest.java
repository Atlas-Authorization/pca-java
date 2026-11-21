package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The shared vectors for the forbid-wins certificate (table) and linked policy templates. */
public class PolicyAuthoringTest {
    static final String DIR = "conformance/";

    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String name) throws Exception {
        return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(DIR + name)));
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Object o) { return (List<Map<String, Object>>) o; }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) for (Object x : (List<?>) o) out.add((String) x);
        return out;
    }

    @Test void forbidCertificateTable() throws Exception {
        List<Map<String, Object>> table = list(load("forbid-certificate-vectors.json").get("table"));
        assertTrue(table.size() >= 19);
        for (Map<String, Object> v : table) {
            List<String> prec = v.containsKey("options") ? strings(m(v.get("options")).get("precedence")) : List.of();
            boolean want = Boolean.TRUE.equals(m(v.get("expect")).get("consistent"));
            assertEquals(want, PolicyAuthoring.forbidCertificateConsistent(v.get("certificate"), prec), String.valueOf(v.get("name")));
        }
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(null, null));
        assertFalse(PolicyAuthoring.forbidCertificateConsistent("x", null));
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(Map.of(), null));
    }

    @Test void policyLinkVectors() throws Exception {
        Map<String, Object> doc = load("policy-link-vectors.json");
        Object def = m(doc.get("template")).get("def");
        assertEquals(m(doc.get("template")).get("digest"), PolicyAuthoring.templateDigest(def));
        for (Map<String, Object> v : list(doc.get("def_errors"))) {
            assertEquals(v.get("expect"), PolicyAuthoring.templateDefError(v.get("def")), String.valueOf(v.get("name")));
        }
        List<Map<String, Object>> inst = list(doc.get("instantiate"));
        assertTrue(inst.size() >= 14);
        for (Map<String, Object> v : inst) {
            PolicyAuthoring.Result r = PolicyAuthoring.instantiateTemplate(def, v.get("slots"));
            Map<String, Object> x = m(v.get("expect"));
            String n = String.valueOf(v.get("name"));
            if (Boolean.TRUE.equals(x.get("ok"))) assertTrue(r.policy != null && IntentJs.jsonEquals(r.policy, x.get("policy")), n + ": " + r.reason);
            else { assertNull(r.policy, n); assertEquals(x.get("reason"), r.reason, n); }
        }
        for (Map<String, Object> v : list(doc.get("verify"))) {
            List<String> trusted = strings(v.get("trusted"));
            String r = "template".equals(v.get("kind")) ? PolicyAuthoring.verifyTemplate(v.get("signed"), trusted) : PolicyAuthoring.verifyTighten(v.get("signed"), trusted);
            Map<String, Object> x = m(v.get("expect"));
            assertEquals(Boolean.TRUE.equals(x.get("ok")), r == null, String.valueOf(v.get("name")));
            if (r != null) assertEquals(x.get("reason"), r, String.valueOf(v.get("name")));
        }
        for (Map<String, Object> v : list(doc.get("ref_errors"))) {
            assertEquals(v.get("expect"), PolicyAuthoring.templateRefError(v.get("ref")), String.valueOf(v.get("name")));
        }
        for (Map<String, Object> v : list(doc.get("resolve"))) {
            PolicyAuthoring.Result r = PolicyAuthoring.resolveLink(v.get("ref"), v.get("registry"));
            Map<String, Object> x = m(v.get("expect"));
            String n = String.valueOf(v.get("name"));
            if (Boolean.TRUE.equals(x.get("ok"))) {
                assertTrue(r.policy != null && IntentJs.jsonEquals(r.policy, x.get("policy")), n + ": " + r.reason);
                assertEquals((long) IntentJs.lng(x.get("overlays")), (long) r.overlays, n);
            } else { assertNull(r.policy, n); assertEquals(x.get("reason"), r.reason, n); }
        }
    }
}
