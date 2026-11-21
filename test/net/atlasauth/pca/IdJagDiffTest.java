package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.idjag.IdJag;
import net.atlasauth.pca.idjag.IdJagVerificationError;
import net.atlasauth.pca.idjag.JtiStore;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Jws;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the ID-JAG / cross-app-access package. */
public class IdJagDiffTest {
    private static final String M = "ref-idjag-java";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Map<String, Object> opt(List<?> a, int i) { return a.size() > i ? m(a.get(i)) : null; }

    private static byte[] seed(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
    }

    @Test void verifyIdJag() throws Exception {
        OracleCases.each(M, "verifyIdJag", a -> {
            final List<Object> consumed = new ArrayList<>();
            Map<String, Object> out = new LinkedHashMap<>();
            try {
                Map<String, Object> opts = null;
                if (a.get(1) != null) {
                    opts = new LinkedHashMap<>(m(a.get(1)));
                    Object jwks = opts.remove("jwks");
                    Object consume = opts.remove("consume");
                    if (jwks != null) opts.put("key", Jws.localJwks(jwks));
                    if (consume != null) {
                        opts.put("consumeJti", (JtiStore) (jti, exp) -> {
                            List<Object> call = new ArrayList<>();
                            call.add(jti);
                            call.add(exp);
                            consumed.add(call);
                            if (consume.equals("throws")) throw new Exception("store down");
                            if (consume.equals("seen")) return Boolean.FALSE;
                            if (consume.equals("truthy")) return Integer.valueOf(1);
                            return Boolean.TRUE;
                        });
                    }
                }
                if (!(a.get(0) instanceof String)) throw new IdJagVerificationError("invalid_token", "jwt must be a non-empty string");
                Map<String, Object> grant = IdJag.verifyIdJag((String) a.get(0), opts);
                out.put("ok", Boolean.TRUE);
                out.put("grant", grant);
            } catch (IdJagVerificationError e) {
                out.put("ok", Boolean.FALSE);
                out.put("code", e.code());
            } catch (RuntimeException e) {
                out.put("ok", Boolean.FALSE);
                out.put("code", "other");
            }
            out.put("consumed", consumed);
            return out;
        });
    }

    @Test void idJagToPcaPrincipal() throws Exception { OracleCases.each(M, "idJagToPcaPrincipal", a -> IdJag.idJagToPcaPrincipal(m(a.get(0)), opt(a, 1))); }

    @Test void idJagToCapability() throws Exception {
        OracleCases.each(M, "idJagToCapability", a -> {
            Map<String, Object> o = a.get(1) == null ? null : new LinkedHashMap<>(m(a.get(1)));
            if (o != null && o.containsKey("principalSecretLabel")) o.put("principalSecret", seed((String) o.remove("principalSecretLabel")));
            return IdJag.idJagToCapability(a.get(0) == null ? null : m(a.get(0)), o);
        });
    }

    @Test void idJagToCapabilitySuite() throws Exception {
        OracleCases.each("ref-idjag-suite-java", "idJagToCapabilitySuite", a -> {
            String alg = (String) a.get(2);
            Keys.EdKey ed = Keys.edFromSeed(seed((String) a.get(1)));
            Keys.SuiteKey suite = "ed25519".equals(alg) ? Keys.ed25519(ed)
                : Keys.suite(alg, ed, Keys.pqFromSeed(alg.endsWith("ml-dsa-87") ? Pq.Prim.ML_DSA_87 : Pq.Prim.ML_DSA_65, Keys.unb64u((String) a.get(3))));
            String pub = a.size() > 4 && a.get(4) != null ? (String) a.get(4) : ed.id();
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("principalSecret", seed((String) a.get(1)));
            o.put("principalPublic", pub);
            o.put("holder", Keys.edFromSeed(seed("idjag/holder")).id());
            o.put("suite", suite);
            Map<String, Object> r = IdJag.idJagToCapability(m(a.get(0)), o);
            Map<String, Object> cap = new LinkedHashMap<>(m(r.get("capability")));
            Object sig = cap.remove("sig");
            Object pqSig = cap.remove("pq_sig");
            Map<String, Object> pins = new LinkedHashMap<>();
            if (cap.get("pq_pk") != null) pins.put(pub, cap.get("pq_pk"));
            List<Object> chain = new ArrayList<>();
            chain.add(r.get("capability"));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("capability", cap);
            out.put("sig_len", sig instanceof String ? (Object) Integer.valueOf(Keys.unb64u((String) sig).length) : null);
            out.put("pq_sig_len", pqSig instanceof String ? (Object) Integer.valueOf(Keys.unb64u((String) pqSig).length) : null);
            out.put("principal", r.get("principal"));
            out.put("scopes", r.get("scopes"));
            out.put("ok", "".equals(Pca.verifyChain(chain, pub, true, null, pins, null)));
            return out;
        });
    }

    @Test void isIdJagAuthorityCaveat() throws Exception { OracleCases.each(M, "isIdJagAuthorityCaveat", a -> IdJag.isIdJagAuthorityCaveat(a.get(0))); }
    @Test void isIdJagProvenanceCaveat() throws Exception { OracleCases.each(M, "isIdJagProvenanceCaveat", a -> IdJag.isIdJagProvenanceCaveat(a.get(0))); }
    @Test void readIdJagAuthority() throws Exception { OracleCases.each(M, "readIdJagAuthority", a -> IdJag.readIdJagAuthority(a.get(0))); }
    @Test void readIdJagProvenance() throws Exception { OracleCases.each(M, "readIdJagProvenance", a -> IdJag.readIdJagProvenance(a.get(0))); }
    @Test void tokenExchangeRequest() throws Exception { OracleCases.each(M, "tokenExchangeRequest", a -> IdJag.tokenExchangeRequest(a.get(0) == null ? null : m(a.get(0)))); }
    @Test void jwtBearerAssertion() throws Exception { OracleCases.each(M, "jwtBearerAssertion", a -> IdJag.jwtBearerAssertion(a.get(0) == null ? null : m(a.get(0)))); }

    @Test void constants() {
        assertEquals("urn:ietf:params:oauth:grant-type:token-exchange", IdJag.GRANT_TYPE_TOKEN_EXCHANGE);
        assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", IdJag.GRANT_TYPE_JWT_BEARER);
        assertEquals("urn:ietf:params:oauth:token-type:id-jag", IdJag.TOKEN_TYPE_ID_JAG);
        assertEquals("urn:ietf:params:oauth:token-type:id_token", IdJag.TOKEN_TYPE_ID_TOKEN);
        assertEquals("urn:ietf:params:oauth:token-type:access_token", IdJag.TOKEN_TYPE_ACCESS_TOKEN);
        assertEquals("urn:ietf:params:oauth:token-type:jwt", IdJag.TOKEN_TYPE_JWT);
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", IdJag.CLIENT_ASSERTION_TYPE_JWT_BEARER);
        assertEquals("idjag_authority", IdJag.IDJAG_AUTHORITY_CAVEAT);
        assertEquals("idjag_provenance", IdJag.IDJAG_PROVENANCE_CAVEAT);
        assertEquals(16384, IdJag.MAX_ID_JAG_CHARS);
        assertEquals(JsVal.n(1).raw, "1");
    }
}
