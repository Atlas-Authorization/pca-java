package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import net.atlasauth.pca.ap2.Ap2;
import net.atlasauth.pca.ap2.Chain;
import net.atlasauth.pca.ap2.Constraints;
import net.atlasauth.pca.ap2.Ledger;
import net.atlasauth.pca.ap2.Mandates;
import net.atlasauth.pca.ap2.Sdjwt;
import net.atlasauth.pca.ap2.Settlement;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the AP2 package through the native port. */
public class Ap2DiffTest {
    private static final String M = "ref-ap2";
    private static final double T0 = 1_800_000_000d;

    // ---- plumbing ------------------------------------------------------------------------------------------------------
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static String s(Object o) { return (String) o; }

    private static double d(Object o) { return Double.parseDouble(o.toString()); }

    private static Map<String, Object> mk(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    private static byte[] sha256(String x) throws Exception { return MessageDigest.getInstance("SHA-256").digest(x.getBytes(StandardCharsets.UTF_8)); }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    private static final Map<String, Sdjwt.Ap2KeyPair> KEYS = new HashMap<>();

    /** The private JWK of a label: d = sha256("atlas-pca-conformance/ap2/" + label); the public point is d*G. */
    static Map<String, Object> privJwk(String label) throws Exception {
        byte[] d = sha256("atlas-pca-conformance/ap2/" + label);
        org.bouncycastle.math.ec.ECPoint q = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1").getG().multiply(new BigInteger(1, d)).normalize();
        return mk("kty", "EC", "crv", "P-256", "d", Sdjwt.b64uEncode(d), "x", Sdjwt.b64uEncode(fixed32(q.getAffineXCoord().toBigInteger())),
            "y", Sdjwt.b64uEncode(fixed32(q.getAffineYCoord().toBigInteger())), "kid", label);
    }

    static synchronized Sdjwt.Ap2KeyPair keyFor(String label) throws Exception {
        Sdjwt.Ap2KeyPair k = KEYS.get(label);
        if (k == null) {
            k = Sdjwt.ap2KeyPairFromPrivateJwk(privJwk(label));
            KEYS.put(label, k);
        }
        return k;
    }

    static Map<String, Object> pubOf(String label) throws Exception {
        Map<String, Object> j = keyFor(label).publicJwk;
        return mk("kty", "EC", "crv", "P-256", "x", j.get("x"), "y", j.get("y"));
    }

    /** Counter salts "salt-000000000001" (base64url of the ASCII text), as the reference generator uses. */
    private static Supplier<String> counterSalt() {
        int[] n = {0};
        return () -> Sdjwt.b64uEncode(("salt-" + String.format("%012d", ++n[0])).getBytes(StandardCharsets.US_ASCII));
    }

    /** Every compact JWT's signature segment replaced by SIG (signatures are randomized). */
    static String stripSig(String token) {
        String[] parts = token.split("~", -1);
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")) parts[i] = parts[i].substring(0, parts[i].lastIndexOf('.')) + ".SIG";
        }
        return String.join("~", parts);
    }

    private static String maskReason(String s) { return s == null ? null : s.replaceFirst("(?s)invalid JSON \\(.*\\)$", "invalid JSON (*)"); }

    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : l(o)) out.add((String) x);
        return out;
    }

    private static Function<Map<String, Object>, Map<String, Object>> resolver(Object keys) {
        return h -> {
            Object kid = h.get("kid");
            return keys instanceof Map && kid instanceof String && m(keys).containsKey(kid) ? m(m(keys).get(kid)) : null;
        };
    }

    private static <T extends Chain.VerifyChainOptions> T baseOpts(T o, Map<String, Object> c) {
        o.resolveIssuerKey = resolver(c.get("issuerKeys"));
        o.expectedAudience = (String) c.get("expectedAudience");
        o.expectedNonce = (String) c.get("expectedNonce");
        if (c.containsKey("now")) o.now = d(c.get("now"));
        if (c.containsKey("clockSkewSeconds")) o.clockSkewSeconds = d(c.get("clockSkewSeconds"));
        return o;
    }

    private static Map<String, Object> hopOut(Chain.VerifiedHop h) { return mk("index", h.index, "kind", h.kind, "claims", h.claims, "mandate", h.mandate); }

    private static Map<String, Object> projChain(Chain.ChainResult r) {
        if (!r.ok) {
            Map<String, Object> out = mk("ok", false, "reason", maskReason(r.reason));
            if (r.violations != null) out.put("violations", r.violations);
            return out;
        }
        List<Object> hops = new ArrayList<>();
        for (Chain.VerifiedHop h : r.hops) hops.add(hopOut(h));
        Map<String, Object> out = mk("ok", true, "hops", hops);
        if (r.open != null) {
            out.put("open", r.open);
            out.put("closed", r.closed);
        }
        if (r.checkoutJwt != null) {
            out.put("checkoutJwt", r.checkoutJwt);
            out.put("checkout", r.checkout);
        }
        if (r.openHash != null) out.put("openHash", r.openHash);
        return out;
    }

    private static Map<String, Object> projPurchase(Chain.PurchaseResult r) {
        return r.ok ? mk("ok", true, "checkout", projChain(r.checkout), "payment", projChain(r.payment)) : mk("ok", false, "reason", maskReason(r.reason));
    }

    private static Chain.VerifyPurchaseOptions purchOptsOf(Map<String, Object> c) {
        Chain.VerifyPurchaseOptions o = new Chain.VerifyPurchaseOptions();
        o.resolveIssuerKey = resolver(c.get("issuerKeys"));
        o.resolveMerchantKey = resolver(c.get("merchantKeys"));
        o.checkout = new Chain.Expect(s(m(c.get("checkout")).get("expectedAudience")), s(m(c.get("checkout")).get("expectedNonce")));
        o.payment = new Chain.Expect(s(m(c.get("payment")).get("expectedAudience")), s(m(c.get("payment")).get("expectedNonce")));
        if (c.containsKey("context")) o.context = m(c.get("context"));
        if (c.containsKey("now")) o.now = d(c.get("now"));
        if (c.containsKey("clockSkewSeconds")) o.clockSkewSeconds = d(c.get("clockSkewSeconds"));
        return o;
    }

    private static Map<String, Object> hopProjection(Sdjwt.SdJwtHop h) {
        return mk("raw", h.raw, "jwt", h.jwt, "header", h.header, "payload", h.payload, "disclosures", h.disclosures, "sdAlg", h.sdAlg, "signingInput", h.signingInput, "signature", h.signature);
    }

    private static final Map<String, Object> MERCH = mk("id", "merchant_1", "name", "Demo Merchant", "website", "https://demo-merchant.example");
    private static final Map<String, Object> MERCH2 = mk("id", "merchant_2", "name", "Other Merchant");

    // ---- sdjwt ----------------------------------------------------------------------------------------------------------
    @Test void b64uEncode() throws Exception { OracleCases.each(M, "b64uEncode", a -> Sdjwt.b64uEncode(s(a.get(0)))); }
    @Test void b64uDecode() throws Exception { OracleCases.each(M, "b64uDecode", a -> Sdjwt.b64uDecode(s(a.get(0)), s(a.get(1)))); }
    @Test void parseJson() throws Exception { OracleCases.each(M, "parseJson", a -> Sdjwt.parseJson(s(a.get(0)), s(a.get(1)))); }
    @Test void isSdAlg() throws Exception { OracleCases.each(M, "isSdAlg", a -> Sdjwt.isSdAlg(a.get(0))); }
    @Test void sdDigest() throws Exception { OracleCases.each(M, "sdDigest", a -> a.size() > 1 ? Sdjwt.sdDigest(s(a.get(0)), s(a.get(1))) : Sdjwt.sdDigest(s(a.get(0)))); }
    @Test void assertP256Jwk() throws Exception { OracleCases.each(M, "assertP256Jwk", a -> Sdjwt.assertP256Jwk(a.get(0), s(a.get(1)))); }
    @Test void jwkThumbprint() throws Exception { OracleCases.each(M, "jwkThumbprint", a -> Sdjwt.jwkThumbprint(a.get(0))); }

    @Test void ap2KeyPairFromPrivateJwk() throws Exception {
        OracleCases.each(M, "ap2KeyPairFromPrivateJwk", a -> {
            Map<String, Object> jwk = privJwk(s(a.get(0)));
            jwk.putAll(m(a.get(1)));
            return Sdjwt.ap2KeyPairFromPrivateJwk(jwk).publicJwk;
        });
    }

    @Test void parseSdJwtHop() throws Exception { OracleCases.each(M, "parseSdJwtHop", a -> hopProjection(Sdjwt.parseSdJwtHop(a.get(0)))); }

    @Test void hopSdJwt() throws Exception {
        OracleCases.each(M, "hopSdJwt", a -> {
            Sdjwt.SdJwtHop h = Sdjwt.parseSdJwtHop(a.get(0));
            return Sdjwt.hopSdJwt(h.jwt, h.disclosures);
        });
    }

    @Test void sdHashOf() throws Exception { OracleCases.each(M, "sdHashOf", a -> a.size() > 1 ? Sdjwt.sdHashOf(Sdjwt.parseSdJwtHop(a.get(0)), s(a.get(1))) : Sdjwt.sdHashOf(Sdjwt.parseSdJwtHop(a.get(0)))); }
    @Test void issuerJwtHashOf() throws Exception { OracleCases.each(M, "issuerJwtHashOf", a -> a.size() > 1 ? Sdjwt.issuerJwtHashOf(Sdjwt.parseSdJwtHop(a.get(0)), s(a.get(1))) : Sdjwt.issuerJwtHashOf(Sdjwt.parseSdJwtHop(a.get(0)))); }

    @Test void processDisclosures() throws Exception {
        OracleCases.each(M, "processDisclosures", a -> {
            if (a.size() == 1 && a.get(0) instanceof String) { Sdjwt.SdJwtHop x = Sdjwt.parseSdJwtHop(a.get(0)); return Sdjwt.processDisclosures(x.payload, x.disclosures, x.sdAlg); }
            if (a.size() == 3 && a.get(1) instanceof List && a.get(0) instanceof Map) return Sdjwt.processDisclosures(m(a.get(0)), strings(a.get(1)), s(a.get(2)));
            throw new IllegalArgumentException("bad args");
        });
    }

    @Test void disclosureBuilder() throws Exception {
        OracleCases.each(M, "disclosureBuilder", a -> {
            Sdjwt.DisclosureBuilder b = Sdjwt.disclosureBuilder((String) a.get(0), counterSalt());
            List<Object> results = new ArrayList<>();
            for (Object op : l(a.get(1))) {
                Map<String, Object> o = m(op);
                results.add("element".equals(o.get("kind")) ? b.element(o.get("value")) : b.property(s(o.get("name")), o.get("value")));
            }
            return mk("results", results, "disclosures", b.disclosures);
        });
    }

    @Test void parseJwt() throws Exception {
        OracleCases.each(M, "parseJwt", a -> {
            Sdjwt.ParsedJwt p = Sdjwt.parseJwt(s(a.get(0)), s(a.get(1)));
            return mk("header", p.header, "payload", p.payload, "signingInput", p.signingInput, "signature", p.signature);
        });
    }

    @Test void verifyJwtEs256() throws Exception { OracleCases.each(M, "verifyJwtEs256", a -> Sdjwt.verifyJwtEs256(Sdjwt.parseJwt(s(a.get(0)), "jwt"), m(a.get(1)))); }
    @Test void verifyHopSignature() throws Exception { OracleCases.each(M, "verifyHopSignature", a -> Sdjwt.verifyHopSignature(Sdjwt.parseSdJwtHop(a.get(0)), m(a.get(1)))); }

    @Test void signSdJwt() throws Exception {
        OracleCases.each(M, "signSdJwt", a -> {
            Map<String, Object> x = m(a.get(0));
            return stripSig(Sdjwt.signSdJwt(m(x.get("header")), m(x.get("payload")), strings(x.get("disclosures")), keyFor(s(x.get("key"))).privateKey));
        });
    }

    @Test void signJwtEs256() throws Exception {
        OracleCases.each(M, "signJwtEs256", a -> {
            Map<String, Object> x = m(a.get(0));
            return stripSig(Sdjwt.signJwtEs256(m(x.get("header")), m(x.get("payload")), keyFor(s(x.get("key"))).privateKey));
        });
    }

    // ---- mandates -------------------------------------------------------------------------------------------------------
    @Test void currencyExponent() throws Exception { OracleCases.each(M, "currencyExponent", a -> Mandates.currencyExponent(a.get(0))); }
    @Test void toMinorUnits() throws Exception { OracleCases.each(M, "toMinorUnits", a -> Mandates.toMinorUnits(a.get(0), a.get(1))); }
    @Test void fromMinorUnits() throws Exception { OracleCases.each(M, "fromMinorUnits", a -> Mandates.fromMinorUnits(a.get(0), a.get(1))); }
    @Test void openPaymentMandateProblems() throws Exception { OracleCases.each(M, "openPaymentMandateProblems", a -> Mandates.openPaymentMandateProblems(a.get(0))); }
    @Test void paymentMandateProblems() throws Exception { OracleCases.each(M, "paymentMandateProblems", a -> Mandates.paymentMandateProblems(a.get(0))); }
    @Test void openCheckoutMandateProblems() throws Exception { OracleCases.each(M, "openCheckoutMandateProblems", a -> Mandates.openCheckoutMandateProblems(a.get(0))); }
    @Test void checkoutMandateProblems() throws Exception { OracleCases.each(M, "checkoutMandateProblems", a -> Mandates.checkoutMandateProblems(a.get(0))); }

    @Test void assertValid() throws Exception {
        OracleCases.each(M, "assertValid", a -> {
            Function<Object, List<String>> f;
            switch (s(a.get(0))) {
                case "openPaymentMandateProblems": f = Mandates::openPaymentMandateProblems; break;
                case "paymentMandateProblems": f = Mandates::paymentMandateProblems; break;
                case "openCheckoutMandateProblems": f = Mandates::openCheckoutMandateProblems; break;
                default: f = Mandates::checkoutMandateProblems;
            }
            return Mandates.assertValid(a.get(1), f, s(a.get(2)));
        });
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> mk("VCT_CHECKOUT", Mandates.VCT_CHECKOUT, "VCT_CHECKOUT_OPEN", Mandates.VCT_CHECKOUT_OPEN, "VCT_PAYMENT", Mandates.VCT_PAYMENT,
            "VCT_PAYMENT_OPEN", Mandates.VCT_PAYMENT_OPEN, "PCA_CLAIM", Mandates.PCA_CLAIM, "FREQUENCIES", Mandates.FREQUENCIES, "AP2_COMMIT", Ap2.AP2_COMMIT,
            "PCA_BINDING_VERSION", Ap2.PCA_BINDING_VERSION, "TYP_TERMINAL", Chain.TYP_TERMINAL, "TYP_INTERMEDIATE", Chain.TYP_INTERMEDIATE));
    }

    // ---- constraints ----------------------------------------------------------------------------------------------------
    @Test void merchantMatches() throws Exception { OracleCases.each(M, "merchantMatches", a -> Constraints.merchantMatches(a.get(0), a.get(1))); }

    @Test void checkPaymentConstraints() throws Exception {
        OracleCases.each(M, "checkPaymentConstraints", a -> {
            Map<String, Object> o = m(a.get(2));
            return Constraints.checkPaymentConstraints(m(a.get(0)), m(a.get(1)),
                new Constraints.PaymentCheckOptions((String) o.get("openCheckoutHash"), o.containsKey("context") ? m(o.get("context")) : null, d(o.get("now"))));
        });
    }

    @Test void projectCheckout() throws Exception { OracleCases.each(M, "projectCheckout", a -> Constraints.projectCheckout(m(a.get(0)))); }
    @Test void checkoutTotal() throws Exception { OracleCases.each(M, "checkoutTotal", a -> Constraints.checkoutTotal(m(a.get(0)))); }
    @Test void checkCheckoutConstraints() throws Exception { OracleCases.each(M, "checkCheckoutConstraints", a -> Constraints.checkCheckoutConstraints(m(a.get(0)), m(a.get(1)))); }

    // ---- chain: verification --------------------------------------------------------------------------------------------
    @Test void splitChain() throws Exception { OracleCases.each(M, "splitChain", a -> Chain.splitChain(a.get(0))); }

    @Test void verifyDelegationChain() throws Exception {
        OracleCases.each(M, "verifyDelegationChain", a -> projChain(Chain.verifyDelegationChain(s(a.get(0)), baseOpts(new Chain.VerifyChainOptions(), m(a.get(1))))));
    }

    @Test void verifyKbHop() throws Exception {
        OracleCases.each(M, "verifyKbHop", a -> {
            Map<String, Object> o = m(a.get(3));
            Chain.VerifiedHop prev = new Chain.VerifiedHop(0, "root", Sdjwt.parseSdJwtHop(a.get(1)), new LinkedHashMap<>(), m(a.get(2)));
            Chain.VerifiedHop v = Chain.verifyKbHop(Sdjwt.parseSdJwtHop(a.get(0)), prev,
                new Chain.KbOptions(Boolean.TRUE.equals(o.get("terminal")), (String) o.get("expectedAudience"), (String) o.get("expectedNonce"), d(o.get("now")), d(o.get("skew"))), s(a.get(4)));
            return hopOut(v);
        });
    }

    @Test void verifyCheckoutChain() throws Exception {
        OracleCases.each(M, "verifyCheckoutChain", a -> {
            Map<String, Object> c = m(a.get(1));
            Chain.VerifyCheckoutOptions o = baseOpts(new Chain.VerifyCheckoutOptions(), c);
            o.resolveMerchantKey = resolver(c.get("merchantKeys"));
            return projChain(Chain.verifyCheckoutChain(s(a.get(0)), o));
        });
    }

    @Test void verifyPaymentChain() throws Exception {
        OracleCases.each(M, "verifyPaymentChain", a -> {
            Map<String, Object> c = m(a.get(1));
            Chain.VerifyPaymentOptions o = baseOpts(new Chain.VerifyPaymentOptions(), c);
            o.openCheckoutHash = (String) c.get("openCheckoutHash");
            if (c.containsKey("context")) o.context = m(c.get("context"));
            o.expectedTransactionId = (String) c.get("expectedTransactionId");
            return projChain(Chain.verifyPaymentChain(s(a.get(0)), o));
        });
    }

    @Test void verifyPurchase() throws Exception { OracleCases.each(M, "verifyPurchase", a -> projPurchase(Chain.verifyPurchase(s(a.get(0)), s(a.get(1)), purchOptsOf(m(a.get(2)))))); }

    @Test void redeemPurchase() throws Exception {
        OracleCases.each(M, "redeemPurchase", a -> {
            Object spec = a.get(3);
            List<Object> calls = new ArrayList<>();
            Ledger.PurchaseLedger ledger = "none".equals(spec) ? null : new Ledger.PurchaseLedger() {
                @Override public Object reserve(String h, String t, double amt) throws Exception {
                    calls.add(Arrays.asList("reserve", h, t, amt));
                    Map<String, Object> sp = m(spec);
                    if ("throw".equals(sp.get("mode"))) throw new Exception("down");
                    if ("replayed".equals(sp.get("mode"))) return Ledger.PurchaseLedger.REPLAYED;
                    if ("undefined".equals(sp.get("mode"))) return null;
                    return sp.containsKey("ctx") ? sp.get("ctx") : Constraints.context(0, 0, null);
                }

                @Override public void release(String h, String t) throws Exception {
                    calls.add(Arrays.asList("release", h, t));
                    if (Boolean.TRUE.equals(m(spec).get("releaseThrows"))) throw new Exception("release failed");
                }
            };
            Chain.PurchaseResult r = Ledger.redeemPurchase(s(a.get(0)), s(a.get(1)), purchOptsOf(m(a.get(2))), ledger);
            return mk("result", projPurchase(r), "calls", calls);
        });
    }

    // ---- chain: issuance and presentation -------------------------------------------------------------------------------
    private static void openInput(Chain.OpenMandateCommon in, Map<String, Object> a) throws Exception {
        Chain.MandateIssuer iss = new Chain.MandateIssuer();
        iss.privateKey = keyFor(a.containsKey("issuerKey") ? s(a.get("issuerKey")) : "issuer").privateKey;
        if (a.containsKey("kid")) iss.kid = s(a.get("kid"));
        if (a.containsKey("x5c")) iss.x5c = strings(a.get("x5c"));
        in.issuer = iss;
        in.agentJwk = a.containsKey("agentJwk") ? m(a.get("agentJwk")) : pubOf(a.containsKey("agentKey") ? s(a.get("agentKey")) : "agent");
        if (a.containsKey("iat")) in.iat = d(a.get("iat"));
        if (a.containsKey("exp")) in.exp = d(a.get("exp"));
        if (a.get("pca") instanceof Map || a.get("pca") instanceof List) in.pca = a.get("pca");
        in.sdAlg = (String) a.get("sdAlg");
        in.typ = (String) a.get("typ");
        in.salt = counterSalt();
    }

    @Test void issueOpenPaymentMandate() throws Exception {
        OracleCases.each(M, "issueOpenPaymentMandate", a -> {
            Map<String, Object> x = m(a.get(0));
            Chain.OpenPaymentMandateInput in = new Chain.OpenPaymentMandateInput();
            openInput(in, x);
            in.constraints = l(x.get("constraints"));
            in.payee = x.containsKey("payee") ? m(x.get("payee")) : null;
            in.paymentAmount = x.containsKey("paymentAmount") ? m(x.get("paymentAmount")) : null;
            in.paymentInstrument = x.containsKey("paymentInstrument") ? m(x.get("paymentInstrument")) : null;
            in.pisp = x.containsKey("pisp") ? m(x.get("pisp")) : null;
            in.executionDate = (String) x.get("executionDate");
            return stripSig(Chain.issueOpenPaymentMandate(in));
        });
    }

    @Test void issueOpenCheckoutMandate() throws Exception {
        OracleCases.each(M, "issueOpenCheckoutMandate", a -> {
            Map<String, Object> x = m(a.get(0));
            Chain.OpenCheckoutMandateInput in = new Chain.OpenCheckoutMandateInput();
            openInput(in, x);
            in.constraints = l(x.get("constraints"));
            return stripSig(Chain.issueOpenCheckoutMandate(in));
        });
    }

    private static void hopInput(Chain.ClosedHopCommon in, Map<String, Object> a) throws Exception {
        in.open = s(a.get("open"));
        in.agentKey = keyFor(a.containsKey("agentKey") ? s(a.get("agentKey")) : "agent");
        in.aud = (String) a.get("aud");
        in.nonce = (String) a.get("nonce");
        if (a.containsKey("iat")) in.iat = d(a.get("iat"));
        if (a.containsKey("exp")) in.exp = d(a.get("exp"));
        if (a.get("pca") instanceof Map || a.get("pca") instanceof List) in.pca = a.get("pca");
        in.hashMode = (String) a.get("hashMode");
        in.salt = counterSalt();
    }

    @Test void presentClosedPayment() throws Exception {
        OracleCases.each(M, "presentClosedPayment", a -> {
            Map<String, Object> x = m(a.get(0));
            Chain.ClosedPaymentInput in = new Chain.ClosedPaymentInput();
            hopInput(in, x);
            in.transactionId = (String) x.get("transactionId");
            in.payee = m(x.get("payee"));
            in.paymentAmount = m(x.get("paymentAmount"));
            in.paymentInstrument = m(x.get("paymentInstrument"));
            in.pisp = x.containsKey("pisp") ? m(x.get("pisp")) : null;
            in.executionDate = (String) x.get("executionDate");
            if (x.get("riskData") instanceof Map || x.get("riskData") instanceof List) in.riskData = x.get("riskData");
            return stripSig(Chain.presentClosedPayment(in));
        });
    }

    @Test void presentClosedCheckout() throws Exception {
        OracleCases.each(M, "presentClosedCheckout", a -> {
            Map<String, Object> x = m(a.get(0));
            Chain.ClosedCheckoutInput in = new Chain.ClosedCheckoutInput();
            hopInput(in, x);
            in.checkoutJwt = (String) x.get("checkoutJwt");
            return stripSig(Chain.presentClosedCheckout(in));
        });
    }

    // ---- PCA terms -> AP2 -----------------------------------------------------------------------------------------------
    @Test void ap2BudgetMax() throws Exception { OracleCases.each(M, "ap2BudgetMax", a -> Ap2.ap2BudgetMax(a.get(0), a.get(1))); }
    @Test void ap2BudgetReads() throws Exception { OracleCases.each(M, "ap2BudgetReads", a -> Ap2.ap2BudgetReads(a.get(0), a.get(1))); }
    @Test void riskRatio() throws Exception { OracleCases.each(M, "riskRatio", a -> Ap2.riskRatio(d(a.get(0)), d(a.get(1)))); }
    @Test void pcaBindingNonce() throws Exception { OracleCases.each(M, "pcaBindingNonce", a -> Ap2.pcaBindingNonce(m(a.get(0)))); }
    @Test void paymentConstraintsFromTerms() throws Exception { OracleCases.each(M, "paymentConstraintsFromTerms", a -> Ap2.paymentConstraintsFromTerms(m(a.get(0)), l(a.get(1)), s(a.get(2)))); }
    @Test void pcaOpenClaim() throws Exception { OracleCases.each(M, "pcaOpenClaim", a -> Ap2.pcaOpenClaim(m(a.get(0)))); }

    private static void fromInput(Ap2.FromTermsOptions o, Map<String, Object> x) throws Exception {
        o.issuer = new Chain.MandateIssuer(keyFor("issuer").privateKey, "issuer-1");
        o.agentJwk = pubOf("agent");
        o.merchants = x.containsKey("merchants") ? l(x.get("merchants")) : new ArrayList<Object>(Arrays.asList(MERCH, MERCH2));
        o.iat = x.containsKey("iat") ? d(x.get("iat")) : T0;
        if (x.containsKey("exp")) o.exp = d(x.get("exp"));
        o.salt = counterSalt();
    }

    @Test void openPaymentMandateFromPca() throws Exception {
        OracleCases.each(M, "openPaymentMandateFromPca", a -> {
            Map<String, Object> x = m(a.get(0));
            Ap2.PaymentFromTermsOptions o = new Ap2.PaymentFromTermsOptions();
            fromInput(o, x);
            o.checkoutReference = x.containsKey("checkoutReference") ? s(x.get("checkoutReference")) : "REF";
            return stripSig(Ap2.openPaymentMandateFromPca(m(x.get("mandate")), o));
        });
    }

    @Test void openCheckoutMandateFromPca() throws Exception {
        OracleCases.each(M, "openCheckoutMandateFromPca", a -> {
            Map<String, Object> x = m(a.get(0));
            Ap2.CheckoutFromTermsOptions o = new Ap2.CheckoutFromTermsOptions();
            fromInput(o, x);
            o.lineItems = x.containsKey("lineItems") ? l(x.get("lineItems"))
                : new ArrayList<Object>(Arrays.asList(mk("id", "line_1", "acceptable_items", new ArrayList<Object>(Arrays.asList(mk("id", "sku-1", "title", "Widget"))), "quantity", 2)));
            return stripSig(Ap2.openCheckoutMandateFromPca(m(x.get("mandate")), o));
        });
    }

    @Test void buildPcaPaymentBinding() throws Exception {
        OracleCases.each(M, "buildPcaPaymentBinding", a -> {
            Map<String, Object> x = m(a.get(0));
            Ap2.PcaPaymentBindingInput in = new Ap2.PcaPaymentBindingInput();
            in.mandate = m(x.get("mandate"));
            in.open = s(x.get("open"));
            in.agentJwk = pubOf("agent");
            in.agentSecret = sha256("atlas-pca-conformance/" + s(x.get("agentSeed")));
            in.audience = (String) x.get("audience");
            in.counter = (long) d(x.get("counter"));
            in.transactionId = (String) x.get("transactionId");
            in.payee = m(x.get("payee"));
            in.amount = m(x.get("amount"));
            in.instrumentId = (String) x.get("instrumentId");
            in.category = (String) x.get("category");
            in.now = (long) d(x.get("now"));
            if (x.containsKey("cosign")) { Map<String, Object> cs = m(x.get("cosign")); in.cosign = built -> cs; }
            return Ap2.buildPcaPaymentBinding(in);
        });
    }

    // ---- settlement -----------------------------------------------------------------------------------------------------
    @Test void toAtomicUnits() throws Exception { OracleCases.each(M, "toAtomicUnits", a -> Settlement.toAtomicUnits(m(a.get(0)), a.get(1))); }

    @Test void x402Settlement() throws Exception {
        OracleCases.each(M, "x402Settlement", a -> Settlement.x402Settlement.settle(m(a.get(0)), a.size() > 1 ? Settlement.SettlementContext.fromMap(m(a.get(1))) : null));
    }

    @Test void stripeSptSettlement() throws Exception {
        OracleCases.each(M, "stripeSptSettlement", a -> Settlement.stripeSptSettlement.settle(m(a.get(0)), a.size() > 1 ? Settlement.SettlementContext.fromMap(m(a.get(1))) : null));
    }
}
