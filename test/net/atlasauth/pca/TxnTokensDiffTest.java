package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Jws;
import net.atlasauth.pca.txntokens.SeenTxn;
import net.atlasauth.pca.txntokens.TxnTokenError;
import net.atlasauth.pca.txntokens.TxnTokens;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the Transaction Token package (act projection, mint, verify). */
public class TxnTokensDiffTest {
    private static final String M = "ref-txn-tokens-java";
    private static final long T0 = 1_800_000_000_000L;
    private static final Pattern UUID_RE = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static byte[] seed(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] pubRaw(String label) throws Exception { return Keys.edFromSeed(seed(label)).pub; }

    /** The reference's keyDesc: {label} = the 32-byte seed, {pubLabel} = that seed's raw public key, {len} = that many zero bytes. */
    private static byte[] keyDesc(Object k) throws Exception {
        Map<String, Object> d = m(k);
        if (d.containsKey("label")) return seed((String) d.get("label"));
        if (d.containsKey("pubLabel")) return pubRaw((String) d.get("pubLabel"));
        return new byte[(int) (double) JsVal.num(d.get("len"))];
    }

    @Test void subActChain() throws Exception { OracleCases.each(M, "subActChain", a -> TxnTokens.subActChain(a.get(0))); }
    @Test void actDepth() throws Exception { OracleCases.each(M, "actDepth", a -> TxnTokens.actDepth(a.get(0))); }
    @Test void toRfc8693Act() throws Exception { OracleCases.each(M, "toRfc8693Act", a -> TxnTokens.toRfc8693Act(a.get(0))); }

    @Test void toTransactionToken() throws Exception {
        OracleCases.each(M, "toTransactionToken", a -> {
            Map<String, Object> args = new LinkedHashMap<>(m(a.get(0)));
            Object kd = args.remove("issuerKey");
            if (kd != null) args.put("issuerKey", keyDesc(kd));
            String token = TxnTokens.toTransactionToken(args, () -> T0);
            Jws.Canonical canon = Jws.assertCanonicalCompactJws(token);
            Map<String, Object> payload = new LinkedHashMap<>(canon.payload);
            boolean random = payload.containsKey("jti") || !args.containsKey("txn");
            if (payload.get("jti") instanceof String && UUID_RE.matcher((String) payload.get("jti")).matches()) payload.put("jti", "<uuid>");
            if (!args.containsKey("txn") && payload.get("txn") instanceof String && UUID_RE.matcher((String) payload.get("txn")).matches()) payload.put("txn", "<uuid>");
            boolean verified = false;
            try {
                Map<String, Object> jwk = new LinkedHashMap<>();
                jwk.put("kty", "OKP");
                jwk.put("crv", "Ed25519");
                jwk.put("x", Jws.b64u(pubRaw((String) m(kd).get("label"))));
                Map<String, Object> vo = new LinkedHashMap<>();
                vo.put("algorithms", new ArrayList<Object>(List.of("EdDSA")));
                Jws.jwtVerify(token, canon, jwk, vo, T0);
                verified = true;
            } catch (RuntimeException e) { /* not verified */ }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("header", canon.header);
            out.put("payload", payload);
            out.put("verified", verified);
            if (!random) out.put("token", token);
            return out;
        });
    }

    @Test void fromTransactionToken() throws Exception {
        OracleCases.each(M, "fromTransactionToken", a -> {
            final List<Object> consumed = new ArrayList<>();
            Map<String, Object> out = new LinkedHashMap<>();
            try {
                Map<String, Object> opts = a.get(2) == null ? null : new LinkedHashMap<>(m(a.get(2)));
                if (opts != null) {
                    Object nowMs = opts.remove("nowMs");
                    Object seen = opts.remove("seen");
                    if (nowMs != null) opts.put("now", nowMs);
                    if (seen != null) {
                        opts.put("seenTxn", (SeenTxn) (id, exp) -> {
                            List<Object> call = new ArrayList<>();
                            call.add(id);
                            call.add(exp);
                            consumed.add(call);
                            if (seen.equals("throws")) throw new Exception("store down");
                            if (seen.equals("seen")) return Boolean.TRUE;
                            if (seen.equals("truthy")) return Integer.valueOf(1);
                            return Boolean.FALSE;
                        });
                    }
                }
                Map<String, Object> result = TxnTokens.fromTransactionToken(a.get(0) instanceof String ? (String) a.get(0) : null, keyDesc(a.get(1)), opts, () -> (long) BaseOracle.clockMs(M)); // the reference ran at the header's frozen clock
                out.put("ok", Boolean.TRUE);
                out.put("result", result);
            } catch (TxnTokenError e) {
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

    @Test void constants() {
        assertEquals("txntoken+jwt", TxnTokens.TXN_TOKEN_TYP_DRAFT_11);
        assertEquals(16384, TxnTokens.MAX_TOKEN_CHARS);
    }
}
