package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.acp.Acp;
import net.atlasauth.pca.acp.StripeSpt;
import net.atlasauth.pca.acp.X402Http;
import net.atlasauth.pca.acp.X402V2;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the ACP / x402 package through the native port. */
public class AcpDiffTest {
    private static final String M = "ref-acp";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** A member-readable view of a JSON value: null stays null (a read throws), a primitive or array has no members. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> mm(Object o) { return o == null ? null : o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>(); }

    private static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("v", n(Acp.ACP_DELEGATED_TOKEN_VERSION));
            o.put("t", Acp.ACP_DELEGATED_TOKEN_TYPE);
            o.put("s", Acp.SPEND_CAP_CAVEAT);
            o.put("m", Acp.MERCHANT_ALLOW_CAVEAT);
            o.put("c", Acp.MERCHANT_CATEGORY_CAVEAT);
            o.put("h", Acp.HUMAN_PRESENT_CAVEAT);
            o.put("x1", n(X402V2.X402_VERSION_1));
            o.put("x2", n(X402V2.X402_VERSION_2));
            List<Object> sup = new ArrayList<>();
            for (Integer v : X402V2.X402_SUPPORTED_VERSIONS) sup.add(n(v));
            o.put("sup", sup);
            o.put("pr", X402V2.X402_V2_PAYMENT_REQUIRED_HEADER);
            o.put("ps", X402Http.X402_PAYMENT_SIGNATURE_HEADER);
            o.put("pe", X402Http.X402_PAYMENT_RESPONSE_HEADER);
            Map<String, Object> st = new LinkedHashMap<>();
            st.put("payment_required", n(X402Http.STATUS_PAYMENT_REQUIRED));
            st.put("malformed", n(X402Http.STATUS_MALFORMED));
            st.put("failed", n(X402Http.STATUS_FAILED));
            st.put("internal_error", n(X402Http.STATUS_INTERNAL_ERROR));
            st.put("settled", n(X402Http.STATUS_SETTLED));
            o.put("st", st);
            o.put("spt", StripeSpt.STRIPE_SPT_OBJECT);
            return o;
        });
    }

    // ---- caveats + authority

    @SuppressWarnings("unchecked")
    @Test void caveatBuilders() throws Exception {
        OracleCases.each(M, "spendCapCaveat", a -> a.size() > 1 ? Acp.spendCapCaveat(OracleCases.num(a.get(0)).longValue(), (String) a.get(1)) : Acp.spendCapCaveat(OracleCases.num(a.get(0)).longValue()));
        OracleCases.each(M, "merchantAllowCaveat", a -> Acp.merchantAllowCaveat((List<String>) a.get(0)));
        OracleCases.each(M, "merchantCategoryCaveat", a -> Acp.merchantCategoryCaveat((List<String>) a.get(0)));
        OracleCases.each(M, "humanPresentCaveat", a -> a.isEmpty() ? Acp.humanPresentCaveat() : Acp.humanPresentCaveat((Boolean) a.get(0)));
    }

    @Test void extractPaymentAuthority() throws Exception { OracleCases.each(M, "extractPaymentAuthority", a -> Acp.extractPaymentAuthority(a.get(0))); }

    @Test void checkPaymentAuthority() throws Exception { OracleCases.each(M, "checkPaymentAuthority", a -> Acp.checkPaymentAuthority(m(a.get(0)), m(a.get(1)))); }

    // ---- mint / verify

    @Test void mintDelegatedPaymentToken() throws Exception { OracleCases.each(M, "mintDelegatedPaymentToken", a -> Acp.mintDelegatedPaymentToken(a.get(0), mm(a.get(1)))); }

    /** The oracle's store specs: "once" grants each jti once, "always", "never", "throw", "truthy" (a non-boolean answer, refused); anything else is no store. */
    private static Map<String, Object> withStore(Map<String, Object> op, Set<String> seen) {
        Map<String, Object> o2 = new LinkedHashMap<>(op);
        if (!op.containsKey("singleUse")) return o2;
        Object spec = op.get("singleUse");
        if ("once".equals(spec)) o2.put("singleUse", (Acp.SingleUseStore) (jti, exp) -> seen.add(jti));
        else if ("always".equals(spec)) o2.put("singleUse", (Acp.SingleUseStore) (jti, exp) -> true);
        else if ("never".equals(spec) || "truthy".equals(spec)) o2.put("singleUse", (Acp.SingleUseStore) (jti, exp) -> false);
        else if ("throw".equals(spec)) o2.put("singleUse", (Acp.SingleUseStore) (jti, exp) -> { throw new IllegalStateException("store down"); });
        return o2;
    }

    private static Map<String, Object> norm(Map<String, Object> r) {
        Map<String, Object> out = new LinkedHashMap<>(r);
        if (out.get("reason") instanceof String) out.put("reason", ((String) out.get("reason")).replaceAll("(?s)^(token signature did not verify|bound proof failed to verify): .*$", "$1"));
        if (out.get("pcaResult") instanceof Map) {
            Map<String, Object> pr = new LinkedHashMap<>();
            pr.put("allow", m(out.get("pcaResult")).get("allow"));
            out.put("pcaResult", pr);
        }
        return out;
    }

    @Test void verifyDelegatedPaymentToken() throws Exception {
        OracleCases.each(M, "verifyDelegatedPaymentToken", a -> {
            int times = a.size() > 2 ? (int) (long) OracleCases.num(a.get(2)).doubleValue() : 1;
            Map<String, Object> o2 = withStore(mm(a.get(1)), new HashSet<>());
            List<Object> rs = new ArrayList<>();
            for (int i = 0; i < times; i++) rs.add(norm(Acp.verifyDelegatedPaymentToken(a.get(0), o2)));
            return times == 1 ? rs.get(0) : rs;
        });
    }

    // ---- x402 v1

    @Test void x402Challenge() throws Exception { OracleCases.each(M, "x402Challenge", a -> Acp.x402Challenge((String) a.get(0), mm(a.get(1)))); }

    @Test void x402Settle() throws Exception {
        OracleCases.each(M, "x402Settle", a -> {
            Object vspec = a.get(1);
            Acp.X402Verify verify = p -> {
                if ("throw".equals(vspec)) throw new IllegalStateException("verify down");
                return m(vspec);
            };
            String sspec = a.size() > 2 ? (String) a.get(2) : null;
            Acp.X402Settler settler = null;
            if ("echo".equals(sspec)) settler = (p, c) -> { Map<String, Object> r = new LinkedHashMap<>(); r.put("jti", c.get("jti")); if (m(p).containsKey("token")) r.put("token", m(p).get("token")); return r; }; // an undefined token is absent in the reference
            else if ("value".equals(sspec)) settler = (p, c) -> "receipt-1";
            else if ("throw".equals(sspec)) settler = (p, c) -> { throw new IllegalStateException("settle down"); };
            else if ("undef".equals(sspec)) settler = (p, c) -> null;
            return Acp.x402Settle(a.get(0), verify, settler);
        });
    }

    @Test void acpX402Verifier() throws Exception {
        OracleCases.each(M, "acpX402Verifier", a -> {
            int times = a.size() > 2 ? (int) (long) OracleCases.num(a.get(2)).doubleValue() : 1;
            Acp.X402Verify fn = Acp.acpX402Verifier(withStore(m(a.get(1)), new HashSet<>()));
            List<Object> rs = new ArrayList<>();
            for (int i = 0; i < times; i++) rs.add(norm(fn.verify(a.get(0))));
            return times == 1 ? rs.get(0) : rs;
        });
    }

    @Test void toAcpAllowance() throws Exception { OracleCases.each(M, "toAcpAllowance", a -> Acp.toAcpAllowance(mm(a.get(0)))); }

    // ---- x402 v2

    @Test void problems() throws Exception {
        OracleCases.each(M, "resourceInfoProblems", a -> X402V2.resourceInfoProblems(a.get(0)));
        OracleCases.each(M, "requirementV2Problems", a -> X402V2.requirementV2Problems(a.get(0)));
        OracleCases.each(M, "paymentRequiredV2Problems", a -> X402V2.paymentRequiredV2Problems(a.get(0)));
        OracleCases.each(M, "paymentPayloadV2Problems", a -> X402Http.paymentPayloadV2Problems(a.get(0)));
        OracleCases.each(M, "settlementResponseProblems", a -> X402Http.settlementResponseProblems(a.get(0)));
        OracleCases.each(M, "stripeSptProblems", a -> StripeSpt.stripeSptProblems(a.get(0)));
    }

    @Test void headers() throws Exception {
        OracleCases.each(M, "encodePaymentRequiredHeader", a -> X402V2.encodePaymentRequiredHeader(a.get(0)));
        OracleCases.each(M, "decodePaymentRequiredHeader", a -> X402V2.decodePaymentRequiredHeader(a.get(0)));
        OracleCases.each(M, "encodePaymentSignatureHeader", a -> X402Http.encodePaymentSignatureHeader(a.get(0)));
        OracleCases.each(M, "decodePaymentSignatureHeader", a -> X402Http.decodePaymentSignatureHeader(a.get(0)));
        OracleCases.each(M, "encodePaymentResponseHeader", a -> X402Http.encodePaymentResponseHeader(a.get(0)));
        OracleCases.each(M, "decodePaymentResponseHeader", a -> X402Http.decodePaymentResponseHeader(a.get(0)));
        OracleCases.each(M, "x402PaymentSignatureHeaders", a -> X402Http.x402PaymentSignatureHeaders(a.get(0)));
    }

    @Test void x402ChallengeV2() throws Exception { OracleCases.each(M, "x402ChallengeV2", a -> X402V2.x402ChallengeV2(a.get(0), mm(a.get(1)))); }

    private static List<Integer> versions(Object o) {
        if (o == null) return null;
        List<Integer> out = new ArrayList<>();
        for (Object x : (List<?>) o) { double d = OracleCases.num(x); out.add(d == Math.floor(d) && Math.abs(d) < 1e9 ? (int) d : Integer.MIN_VALUE); }
        return out;
    }

    private static Integer fail(String m) { throw new IllegalStateException("TypeError: " + m); } // a JSON null offered list is not the same as none: the reference reads its length

    @Test void x402Negotiate() throws Exception {
        OracleCases.each(M, "x402Negotiate", a -> a.get(0) == null ? fail("Cannot read properties of null (reading 'length')") : a.size() > 1 ? X402V2.x402Negotiate(versions(a.get(0)), versions(a.get(1))) : X402V2.x402Negotiate(versions(a.get(0))));
    }

    @Test void x402AcceptedMatches() throws Exception { OracleCases.each(M, "x402AcceptedMatches", a -> X402V2.x402AcceptedMatches((List<?>) a.get(0), a.get(1))); }

    @Test void normalizeX402Payload() throws Exception { OracleCases.each(M, "normalizeX402Payload", a -> X402V2.normalizeX402Payload(a.get(0))); }

    @Test void transport() throws Exception {
        OracleCases.each(M, "readPaymentSignature", a -> X402Http.readPaymentSignature(m(a.get(0))));
        OracleCases.each(M, "x402SettlementResponse", a -> X402Http.x402SettlementResponse(m(a.get(0)), a.get(1)));
    }

    // ---- Stripe SPT

    @Test void stripeSpt() throws Exception {
        OracleCases.each(M, "parseStripeSpt", a -> StripeSpt.parseStripeSpt(a.get(0)));
        OracleCases.each(M, "stripeSptUsable", a -> StripeSpt.stripeSptUsable(a.get(0), mm(a.get(1))));
        OracleCases.each(M, "stripeUsageLimitsFor", a -> StripeSpt.stripeUsageLimitsFor(mm(a.get(0))));
        OracleCases.each(M, "stripeSptWithinClaims", a -> StripeSpt.stripeSptWithinClaims(a.get(0), mm(a.get(1))));
    }
}
