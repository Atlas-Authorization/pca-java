package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.KeyPair;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Shared helpers of the vendor verifier tests: the vector replay of one vendor, config parsing, denial assertions, signing. */
final class AttestVendorRows {
    private AttestVendorRows() {}

    static final AttestationBinding BINDING = new AttestationBinding("holder-key", "passport:abc", 0, "nonce-1");
    static final long NOW = 1_800_000_000_000L;

    @SuppressWarnings("unchecked")
    static Map<String, Object> cfg(String json) { return (Map<String, Object>) Json.parseLenient(json); }

    static String constructError(String vendor, String config) {
        try {
            AttestFactory.verifierFromConfig(vendor, cfg(config));
            return null;
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    static HardwareResult run(String vendor, Map<String, Object> config, Map<String, Object> ev, AttestationBinding b, long now) {
        return AttestFactory.verifierFromConfig(vendor, config).verify(ev, b, now);
    }

    static void assertDenied(String name, HardwareResult r, String want, boolean prefix) {
        assertFalse(r.ok, name + ": must be denied");
        assertFalse(r.bound, name + ": bound on a denial");
        assertNull(r.measured, name + ": measured on a denial");
        assertNull(r.hostAsserted, name + ": hostAsserted on a denial");
        if (prefix) assertTrue(r.reason.startsWith(want), name + ": reason '" + r.reason + "' does not start with '" + want + "'");
        else assertEquals(want, r.reason, name);
    }

    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der) + "\n-----END CERTIFICATE-----\n";
    }

    /** An ECDSA signature as raw r||s (P1363) under the key pair, hashing with hash ("SHA256" / "SHA384"). */
    static byte[] signRaw(KeyPair kp, String hash, byte[] msg) {
        try {
            Signature s = Signature.getInstance(hash + "withECDSAinP1363Format");
            s.initSign(kp.getPrivate());
            s.update(msg);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Replays every attestation_vectors row of one vendor (wire form compared through the canonical JSON form). */
    @SuppressWarnings("unchecked")
    static void replayVendor(String vendor) {
        int n = 0;
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> row : AttestVectors.rows("attestation_vectors")) {
            if (!vendor.equals(row.get("vendor"))) continue;
            n++;
            Map<String, Object> got;
            try {
                VendorVerifier v = AttestFactory.verifierFromConfig(vendor, AttestCommon.asRec(row.get("config")));
                Double now = AttestCommon.asFinite(row.get("now"));
                assertTrue(now != null, row.get("id") + ": now is not a number");
                got = v.verify(AttestCommon.asRec(row.get("evidence")), AttestVectors.bindingOf(row.get("expected_binding")), (long) (double) now).wire();
            } catch (AttestException e) {
                got = new LinkedHashMap<>();
                got.put("construct_error", e.getMessage());
            }
            Map<String, Object> exp = new LinkedHashMap<>((Map<String, Object>) row.get("expect"));
            Map<String, Object> gotN = new LinkedHashMap<>(got);
            if ("prefix".equals(exp.get("reason_match"))) {
                String prefix = (String) exp.get("reason_prefix");
                Object reason = gotN.get("reason");
                if (!(reason instanceof String) || !((String) reason).startsWith(prefix)) {
                    failures.add(row.get("id") + ": reason " + reason + " does not start with " + prefix);
                    continue;
                }
                gotN.remove("reason");
                exp.remove("reason");
            }
            exp.remove("reason_match");
            exp.remove("reason_prefix");
            String g = AttestVectors.canon(gotN);
            String w = AttestVectors.canon(exp);
            if (!g.equals(w)) failures.add(row.get("id") + " (intent " + row.get("intent") + ")\n got  " + g + "\n want " + w);
        }
        assertTrue(n > 0, "no attestation vectors for " + vendor);
        if (!failures.isEmpty()) fail(failures.size() + " of " + n + " " + vendor + " vectors disagree:\n" + String.join("\n", failures));
    }
}
