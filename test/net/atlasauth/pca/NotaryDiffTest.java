package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.atlasauth.pca.notary.Notary;
import org.junit.jupiter.api.Test;

class NotaryDiffTest {
    private static final String M = "ref-notary";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static boolean isBytes(Object o) { return o instanceof Map && ((Map<?, ?>) o).containsKey("$bytes"); }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) map(o).get("$bytes")); }

    /** The oracle's key forms: a b64u string, {"$bytes"} public bytes, a {secretKey, publicKey} pair; anything else is passed through (and refused). */
    private static Object keyArg(Object o) {
        if (isBytes(o)) return bytes(o);
        if (o instanceof Map) {
            Map<String, Object> m = map(o);
            if (isBytes(m.get("secretKey")) && isBytes(m.get("publicKey"))) return Keys.edFromSeed(bytes(m.get("secretKey")));
        }
        return o;
    }

    /** The oracle's salts: salt_i = sha256("notary-oracle-salt/" + i)[:16], the counter restarting at 0 for every call. */
    private static Supplier<byte[]> salts() {
        int[] i = {0};
        return () -> {
            try {
                return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(("notary-oracle-salt/" + i[0]++).getBytes(StandardCharsets.UTF_8)), 16);
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        };
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("BODY_COMMIT_ALG", Notary.BODY_COMMIT_ALG);
            m.put("ATTESTED_FACT_CAVEAT", Notary.ATTESTED_FACT_CAVEAT);
            return m;
        });
    }

    @Test void notaryMessage() throws Exception { OracleCases.each(M, "notaryMessage", a -> Notary.notaryMessage(a.get(0))); }

    @Test void notarizeResponse() throws Exception {
        OracleCases.each(M, "notarizeResponse", a -> {
            Map<String, Object> opts = map(a.get(1));
            Keys.EdKey key = (Keys.EdKey) keyArg(opts.get("notaryKey"));
            Notary.NotarizeOptions o = new Notary.NotarizeOptions(key);
            o.observedAt = opts.get("observedAt");
            o.textChunkSize = opts.get("textChunkSize");
            o.salt = salts();
            return Notary.notarizeResponse(a.get(0) == null ? null : map(a.get(0)), o).toMap();
        });
    }

    @Test void discloseField() throws Exception { OracleCases.each(M, "discloseField", a -> Notary.discloseField(a.get(0), a.get(1), a.get(2))); }

    @Test void verifyNotaryAttestation() throws Exception {
        OracleCases.each(M, "verifyNotaryAttestation", a -> Notary.verifyNotaryAttestation(a.get(0), keyArg(a.get(1))));
    }

    @Test void verifyDisclosedField() throws Exception {
        OracleCases.each(M, "verifyDisclosedField", a -> Notary.verifyDisclosedField(a.get(0), a.get(1), keyArg(a.get(2))));
    }

    @Test void factRef() throws Exception { OracleCases.each(M, "factRef", a -> Notary.factRef(a.get(0))); }

    @Test void bindFactToPcActn() throws Exception { OracleCases.each(M, "bindFactToPcActn", a -> Notary.bindFactToPcActn(a.get(0), a.get(1))); }

    @Test void factMatchesPcActn() throws Exception { OracleCases.each(M, "factMatchesPcActn", a -> Notary.factMatchesPcActn(a.get(0), a.get(1))); }

    @Test void requireAttestedFact() throws Exception {
        OracleCases.each(M, "requireAttestedFact", a -> {
            Map<String, Object> opts = new LinkedHashMap<>(map(a.get(0)));
            if (opts.containsKey("notary")) opts.put("notary", keyArg(opts.get("notary")));
            return Notary.requireAttestedFact(opts);
        });
    }

    @Test void isAttestedFactCaveat() throws Exception { OracleCases.each(M, "isAttestedFactCaveat", a -> Notary.isAttestedFactCaveat(a.get(0))); }

    @Test void notaryKeyUsable() throws Exception { OracleCases.each(M, "notaryKeyUsable", a -> Notary.notaryKeyUsable(a.get(0), a.get(1), a.get(2))); }

    @Test void evaluateAttestedFactCaveat() throws Exception {
        OracleCases.each(M, "evaluateAttestedFactCaveat", a ->
            a.size() > 2 ? Notary.evaluateAttestedFactCaveat(a.get(0), a.get(1), a.get(2) == null ? null : map(a.get(2)))
                : Notary.evaluateAttestedFactCaveat(a.get(0), a.get(1)));
    }
}
