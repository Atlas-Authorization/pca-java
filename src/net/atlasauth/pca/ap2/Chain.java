package net.atlasauth.pca.ap2;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import net.atlasauth.pca.ap2.Sdjwt.DisclosureBuilder;
import net.atlasauth.pca.ap2.Sdjwt.SdJwtHop;

/**
 * AP2 mandate issuance, presentation and verification.
 *
 * <p>Wire format: a mandate is the single object in an SD-JWT's {@code delegate_payload} array, itself an array-element
 * disclosure. An <em>open</em> mandate is signed by the issuer (the user's trusted surface / agent provider) and names the
 * agent's key in {@code cnf.jwk}. A <em>closed</em> mandate is a KB-SD-JWT hop ({@code typ: kb+sd-jwt}) signed by that agent key,
 * carrying {@code iat}, {@code aud}, {@code nonce} and an {@code sd_hash} over the preceding hop. Hops are joined by
 * {@code ~~}. That hop is AP2's key-binding mechanism; no trailing RFC 9901 KB-JWT is used or accepted.
 *
 * <p>Claims, mandates and keys (JWKs) are parsed JSON (Map, List, String, Boolean, Json.Num, null).
 */
public final class Chain {
    private Chain() {}

    // ---------------------------------------------------------------------------------------------
    // issuing open mandates
    // ---------------------------------------------------------------------------------------------

    /** The signer of an open mandate: the user's trusted surface or agent provider (an ES256 key). */
    public static final class MandateIssuer {
        public PrivateKey privateKey;
        /** {@code kid} header; a verifier's key resolver maps it to the public key. */
        public String kid;
        /** Optional {@code x5c} header (base64 DER certificates); chain validation is the resolver's job. */
        public List<String> x5c;

        public MandateIssuer() {}

        public MandateIssuer(PrivateKey privateKey, String kid) {
            this.privateKey = privateKey;
            this.kid = kid;
        }
    }

    /** Fields shared by every open mandate. Times are epoch seconds. */
    public static class OpenMandateCommon {
        public MandateIssuer issuer;
        /** The agent's public key (JWK); becomes {@code cnf.jwk} and is the only key that can sign the closed mandate. */
        public Map<String, Object> agentJwk;
        public double iat = Double.NaN;
        /** Required: an open mandate must be bounded in time. */
        public double exp = Double.NaN;
        /** {@code x_pca} claim (PCA's proof of the grant): a JSON object (anything else fails validation). */
        public Object pca;
        public String sdAlg;
        /** Salt source (tests inject a deterministic one). */
        public Supplier<String> salt;
        /** Root {@code typ} header; the reference SDK imposes none (default {@code dc+sd-jwt}). */
        public String typ;
    }

    private static final String ROOT_TYP = "dc+sd-jwt";

    private static String signRoot(OpenMandateCommon c, Map<String, Object> mandate, DisclosureBuilder b) {
        Map<String, Object> element = b.element(mandate);
        Map<String, Object> header = Js.m("typ", c.typ != null ? c.typ : ROOT_TYP);
        if (c.issuer.kid != null) header.put("kid", c.issuer.kid);
        if (c.issuer.x5c != null) header.put("x5c", new ArrayList<Object>(c.issuer.x5c));
        return Sdjwt.signSdJwt(header, Js.m("delegate_payload", Js.l(element), "_sd_alg", c.sdAlg != null ? c.sdAlg : "sha-256"), b.disclosures, c.issuer.privateKey);
    }

    private static Map<String, Object> commonClaims(OpenMandateCommon c) {
        Map<String, Object> jwk = Sdjwt.assertP256Jwk(c.agentJwk, "agentJwk");
        if (!Js.isSafeInteger(c.iat) || !Js.isSafeInteger(c.exp) || c.exp <= c.iat) throw new Ap2Error("open mandate: need integer iat < exp (epoch seconds)");
        Map<String, Object> out = Js.m("cnf", Js.m("jwk", Js.m("crv", "P-256", "kty", "EC", "x", jwk.get("x"), "y", jwk.get("y"))), "iat", Js.n(c.iat), "exp", Js.n(c.exp));
        if (Js.truthy(c.pca)) out.put(Mandates.PCA_CLAIM, c.pca);
        return out;
    }

    /** Wrap the selectively-disclosable arrays of a payment constraint ({@code allowed} payees / instruments). */
    private static Object sdPaymentConstraint(Object c, DisclosureBuilder b) {
        Object type = Js.get(c, "type");
        if ("payment.allowed_payees".equals(type) || "payment.allowed_payment_instruments".equals(type)) {
            List<Object> allowed = new ArrayList<>();
            for (Object x : Js.arr(Js.get(c, "allowed"))) allowed.add(b.element(x));
            return Js.m("type", type, "allowed", allowed);
        }
        return c;
    }

    private static Object sdCheckoutConstraint(Object c, DisclosureBuilder b) {
        Object type = Js.get(c, "type");
        if ("checkout.allowed_merchants".equals(type)) {
            List<Object> allowed = new ArrayList<>();
            for (Object x : Js.arr(Js.get(c, "allowed"))) allowed.add(b.element(x));
            return Js.m("type", type, "allowed", allowed);
        }
        List<Object> items = new ArrayList<>();
        for (Object it : Js.arr(Js.get(c, "items"))) {
            List<Object> acceptable = new ArrayList<>();
            for (Object x : Js.arr(Js.get(it, "acceptable_items"))) acceptable.add(b.element(x));
            items.add(Js.m("id", Js.get(it, "id"), "acceptable_items", acceptable, "quantity", Js.get(it, "quantity")));
        }
        return Js.m("type", type, "items", items);
    }

    /** Inputs of {@link #issueOpenPaymentMandate}. */
    public static final class OpenPaymentMandateInput extends OpenMandateCommon {
        public List<Object> constraints;
        public Map<String, Object> payee;
        public Map<String, Object> paymentAmount;
        public Map<String, Object> paymentInstrument;
        public Map<String, Object> pisp;
        public String executionDate;
    }

    /** Issue an open Payment Mandate ({@code mandate.payment.open.1}) as a signed SD-JWT. */
    public static String issueOpenPaymentMandate(OpenPaymentMandateInput in) {
        DisclosureBuilder b = Sdjwt.disclosureBuilder(in.sdAlg, in.salt);
        List<Object> wrapped = new ArrayList<>();
        for (Object c : in.constraints) wrapped.add(sdPaymentConstraint(c, b));
        Map<String, Object> mandate = Js.m("vct", Mandates.VCT_PAYMENT_OPEN, "constraints", wrapped);
        if (in.payee != null) mandate.put("payee", in.payee);
        if (in.paymentAmount != null) mandate.put("payment_amount", in.paymentAmount);
        if (in.paymentInstrument != null) mandate.put("payment_instrument", in.paymentInstrument);
        if (in.pisp != null) mandate.put("pisp", in.pisp);
        if (in.executionDate != null) mandate.put("execution_date", in.executionDate);
        mandate.putAll(commonClaims(in));
        assertWellFormed(mandate, Mandates::openPaymentMandateProblems, "open payment mandate", in.constraints);
        return signRoot(in, mandate, b);
    }

    /** Inputs of {@link #issueOpenCheckoutMandate}. */
    public static final class OpenCheckoutMandateInput extends OpenMandateCommon {
        public List<Object> constraints;
    }

    /** Issue an open Checkout Mandate ({@code mandate.checkout.open.1}) as a signed SD-JWT. */
    public static String issueOpenCheckoutMandate(OpenCheckoutMandateInput in) {
        DisclosureBuilder b = Sdjwt.disclosureBuilder(in.sdAlg, in.salt);
        List<Object> wrapped = new ArrayList<>();
        for (Object c : in.constraints) wrapped.add(sdCheckoutConstraint(c, b));
        Map<String, Object> mandate = Js.m("vct", Mandates.VCT_CHECKOUT_OPEN, "constraints", wrapped);
        mandate.putAll(commonClaims(in));
        assertWellFormed(mandate, Mandates::openCheckoutMandateProblems, "open checkout mandate", in.constraints);
        return signRoot(in, mandate, b);
    }

    /** Validate the <em>plain</em> claims (before selective-disclosure wrapping) so a bad input fails at issuance. */
    private static void assertWellFormed(Map<String, Object> wrapped, Function<Object, List<String>> problems, String what, List<Object> plainConstraints) {
        Map<String, Object> plain = new LinkedHashMap<>(wrapped);
        plain.put("constraints", plainConstraints);
        List<String> p = problems.apply(plain);
        if (!p.isEmpty()) throw new Ap2Error(what + ": " + String.join("; ", p));
    }

    // ---------------------------------------------------------------------------------------------
    // presenting closed mandates (KB-SD-JWT hops)
    // ---------------------------------------------------------------------------------------------

    /** Fields shared by every closed mandate hop. */
    public static class ClosedHopCommon {
        /** The preceding token (an open mandate, or a chain ending in an intermediate hop). */
        public String open;
        /** The agent's key pair: its public key must be the open mandate's {@code cnf.jwk}. */
        public Sdjwt.Ap2KeyPair agentKey;
        /** Audience of this hop (the merchant for a checkout, the credential provider for a payment). */
        public String aud;
        /** Verifier-supplied nonce; the verifier checks it on receipt. */
        public String nonce;
        /** Issued-at, epoch seconds. */
        public double iat = Double.NaN;
        /** Optional mandate-level expiry, epoch seconds. */
        public Double exp;
        public Object pca;
        /** Binding claim: {@code sd_hash} (default; pins the preceding hop's disclosures) or {@code issuer_jwt_hash}. */
        public String hashMode;
        public Supplier<String> salt;
    }

    private static String presentHop(ClosedHopCommon c, Function<DisclosureBuilder, Map<String, Object>> build) {
        if (c.aud == null || c.aud.isEmpty() || c.nonce == null || c.nonce.isEmpty()) throw new Ap2Error("closed mandate: aud and nonce are required");
        if (!Js.isSafeInteger(c.iat)) throw new Ap2Error("closed mandate: iat must be an integer");
        SdJwtHop prev = Sdjwt.parseSdJwtHop(c.open);
        DisclosureBuilder b = Sdjwt.disclosureBuilder(prev.sdAlg, c.salt);
        Map<String, Object> mandate = build.apply(b);
        Map<String, Object> element = b.element(mandate);
        String mode = c.hashMode != null ? c.hashMode : "sd_hash";
        Map<String, Object> payload = Js.m("delegate_payload", Js.l(element), "iat", Js.n(c.iat), "aud", c.aud, "nonce", c.nonce);
        payload.put(mode, mode.equals("sd_hash") ? Sdjwt.sdHashOf(prev) : Sdjwt.issuerJwtHashOf(prev));
        payload.put("_sd_alg", prev.sdAlg);
        String hop = Sdjwt.signSdJwt(Js.m("typ", "kb+sd-jwt"), payload, b.disclosures, c.agentKey.privateKey);
        // Hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~".
        return c.open + "~" + hop;
    }

    /** Inputs of {@link #presentClosedPayment}. */
    public static final class ClosedPaymentInput extends ClosedHopCommon {
        /** Hash of the closed checkout's {@code checkout_jwt} (= the closed checkout mandate's {@code checkout_hash}). */
        public String transactionId;
        public Map<String, Object> payee;
        public Map<String, Object> paymentAmount;
        public Map<String, Object> paymentInstrument;
        public Map<String, Object> pisp;
        public String executionDate;
        public Object riskData;
    }

    /** Present a closed Payment Mandate ({@code mandate.payment.1}) on top of an open payment mandate. */
    public static String presentClosedPayment(ClosedPaymentInput in) {
        return presentHop(in, b -> {
            Map<String, Object> mandate = Js.m("vct", Mandates.VCT_PAYMENT, "transaction_id", in.transactionId, "payee", in.payee, "payment_amount", in.paymentAmount, "payment_instrument", in.paymentInstrument);
            if (in.pisp != null) mandate.put("pisp", in.pisp);
            if (in.executionDate != null) mandate.put("execution_date", in.executionDate);
            if (Js.truthy(in.riskData)) mandate.put("risk_data", in.riskData);
            if (in.exp != null) mandate.put("exp", Js.n((double) in.exp));
            if (Js.truthy(in.pca)) mandate.put(Mandates.PCA_CLAIM, in.pca);
            List<String> p = Mandates.paymentMandateProblems(mandate);
            if (!p.isEmpty()) throw new Ap2Error("closed payment mandate: " + String.join("; ", p));
            return mandate;
        });
    }

    /** Inputs of {@link #presentClosedCheckout}. */
    public static final class ClosedCheckoutInput extends ClosedHopCommon {
        /** The merchant-signed checkout JWT (compact). */
        public String checkoutJwt;
    }

    /** Present a closed Checkout Mandate ({@code mandate.checkout.1}) on top of an open checkout mandate. */
    public static String presentClosedCheckout(ClosedCheckoutInput in) {
        return presentHop(in, b -> {
            String prevAlg = Sdjwt.parseSdJwtHop(in.open).sdAlg;
            Map<String, Object> mandate = Js.m("_sd", Js.l(b.property("checkout_jwt", in.checkoutJwt)), "vct", Mandates.VCT_CHECKOUT, "checkout_hash", Sdjwt.sdDigest(in.checkoutJwt, prevAlg));
            if (in.exp != null) mandate.put("exp", Js.n((double) in.exp));
            if (Js.truthy(in.pca)) mandate.put(Mandates.PCA_CLAIM, in.pca);
            Map<String, Object> full = new LinkedHashMap<>(mandate);
            full.put("checkout_jwt", in.checkoutJwt);
            List<String> p = Mandates.checkoutMandateProblems(full);
            if (!p.isEmpty()) throw new Ap2Error("closed checkout mandate: " + String.join("; ", p));
            return mandate;
        });
    }

    // ---------------------------------------------------------------------------------------------
    // verifying a delegation chain
    // ---------------------------------------------------------------------------------------------

    public static final List<String> TYP_TERMINAL = Collections.unmodifiableList(Arrays.asList("kb+sd-jwt", "kb-sd-jwt"));
    public static final List<String> TYP_INTERMEDIATE = Collections.unmodifiableList(Arrays.asList("kb+sd-jwt+kb", "kb-sd-jwt+kb"));
    private static final int MAX_HOPS = 8;

    /** One verified hop of a chain. */
    public static final class VerifiedHop {
        public int index;
        /** {@code root}, {@code intermediate} or {@code terminal}. */
        public final String kind;
        public final SdJwtHop hop;
        /** Hop-level claims after disclosure processing. */
        public final Map<String, Object> claims;
        /** The single mandate object disclosed in {@code delegate_payload}. */
        public final Map<String, Object> mandate;

        public VerifiedHop(int index, String kind, SdJwtHop hop, Map<String, Object> claims, Map<String, Object> mandate) {
            this.index = index;
            this.kind = kind;
            this.hop = hop;
            this.claims = claims;
            this.mandate = mandate;
        }
    }

    /** Options of {@link #verifyDelegationChain}. */
    public static class VerifyChainOptions {
        /** Resolve the root hop's public key from its header ({@code kid} / {@code x5c}); return null to refuse. */
        public Function<Map<String, Object>, Map<String, Object>> resolveIssuerKey;
        /** The terminal hop's {@code aud} must equal this. Required: a verifier that does not name itself cannot detect redirection. */
        public String expectedAudience;
        /** The terminal hop's {@code nonce} must equal this. Required: it is the replay defence. */
        public String expectedNonce;
        /** Verification time, epoch seconds (default: now). */
        public Double now;
        /** Tolerated clock skew in seconds (default 60). */
        public Double clockSkewSeconds;
    }

    /**
     * The outcome of a chain verification. A failure carries {@code reason} (and {@code violations} when the open mandate's
     * constraints were violated); a success carries {@code hops}, and for the typed chains the open / closed mandates.
     */
    public static final class ChainResult {
        public boolean ok;
        public String reason;
        public List<String> violations;
        public List<VerifiedHop> hops;
        public Map<String, Object> open;
        public Map<String, Object> closed;
        /** Checkout chain only: the merchant-signed checkout JWT and its projection. */
        public String checkoutJwt;
        public Map<String, Object> checkout;
        /** {@code sd_hash} of the open mandate token. */
        public String openHash;

        static ChainResult fail(String reason) {
            ChainResult r = new ChainResult();
            r.reason = reason;
            return r;
        }
    }

    /** Split a {@code ~~}-joined chain into hops, each restored to {@code <jwt>~<d>...~}. */
    public static List<String> splitChain(Object tokenObj) {
        if (!(tokenObj instanceof String) || ((String) tokenObj).isEmpty()) throw new Ap2Error("chain: empty");
        String[] parts = ((String) tokenObj).split("~~", -1);
        if (parts.length > MAX_HOPS) throw new Ap2Error("chain: more than " + MAX_HOPS + " hops");
        List<String> out = new ArrayList<>();
        for (int i = 0; i < parts.length; i++) out.add(i == parts.length - 1 ? parts[i] : parts[i] + "~");
        return out;
    }

    private static void checkTimes(String label, Map<String, Object> o, double now, double skew) {
        if (o.containsKey("exp")) {
            Object exp = o.get("exp");
            if (!Js.isSafeInteger(exp) || Js.isNegZero(Js.num(exp))) throw new Ap2Error(label + ": exp must be an integer");
            if (!(Double.isFinite(now) && Double.isFinite(skew) && now <= Js.num(exp) + skew)) throw new Ap2Error(label + ": expired at " + Js.str(exp));
        }
        if (o.containsKey("iat")) {
            Object iat = o.get("iat");
            if (!Js.isSafeInteger(iat) || Js.isNegZero(Js.num(iat))) throw new Ap2Error(label + ": iat must be an integer");
            if (!(Double.isFinite(now) && Double.isFinite(skew) && Js.num(iat) <= now + skew)) throw new Ap2Error(label + ": iat is in the future");
        }
    }

    private static Map<String, Object> delegateMandate(Map<String, Object> claims, String label) {
        Object dp = claims.get("delegate_payload");
        if (!(dp instanceof List)) throw new Ap2Error(label + ": delegate_payload missing");
        List<Object> l = Js.arr(dp);
        if (l.size() != 1 || !Js.isObj(l.get(0))) throw new Ap2Error(label + ": delegate_payload must disclose exactly one mandate (got " + l.size() + ")");
        return Js.obj(l.get(0));
    }

    private static Map<String, Object> cnfJwk(Map<String, Object> mandate, String label) {
        Object cnf = mandate.get("cnf");
        if (!Js.isObj(cnf) || !Js.isObj(Js.get(cnf, "jwk"))) throw new Ap2Error(label + ": no cnf.jwk to delegate to");
        return Sdjwt.assertP256Jwk(Js.get(cnf, "jwk"), label + " cnf.jwk");
    }

    /** What {@link #verifyKbHop} needs besides the hops. */
    public static final class KbOptions {
        public boolean terminal;
        public String expectedAudience;
        public String expectedNonce;
        public double now;
        public double skew;

        public KbOptions(boolean terminal, String expectedAudience, String expectedNonce, double now, double skew) {
            this.terminal = terminal;
            this.expectedAudience = expectedAudience;
            this.expectedNonce = expectedNonce;
            this.now = now;
            this.skew = skew;
        }
    }

    /** Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce). */
    public static VerifiedHop verifyKbHop(SdJwtHop hop, VerifiedHop prev, KbOptions o, String label) {
        Object typ = hop.header.get("typ");
        List<String> allowed = o.terminal ? TYP_TERMINAL : TYP_INTERMEDIATE;
        if (!(typ instanceof String) || !allowed.contains(typ)) throw new Ap2Error(label + ": typ must be one of " + String.join(", ", allowed));
        if (hop.header.containsKey("crit")) throw new Ap2Error(label + ": crit headers are not supported");
        Map<String, Object> key = cnfJwk(prev.mandate, "preceding mandate");
        if (!Sdjwt.verifyHopSignature(hop, key)) throw new Ap2Error(label + ": signature does not verify under the preceding mandate's cnf.jwk");
        Map<String, Object> claims = Sdjwt.processDisclosures(hop.payload, hop.disclosures, hop.sdAlg);
        boolean hasSd = claims.containsKey("sd_hash");
        boolean hasIss = claims.containsKey("issuer_jwt_hash");
        if (hasSd == hasIss) throw new Ap2Error(label + ": exactly one of sd_hash / issuer_jwt_hash is required");
        String expected = hasSd ? Sdjwt.sdHashOf(prev.hop) : Sdjwt.issuerJwtHashOf(prev.hop);
        Object actual = hasSd ? claims.get("sd_hash") : claims.get("issuer_jwt_hash");
        if (!expected.equals(actual)) throw new Ap2Error(label + ": " + (hasSd ? "sd_hash" : "issuer_jwt_hash") + " does not match the preceding hop");
        if (!claims.containsKey("iat")) throw new Ap2Error(label + ": iat is required");
        checkTimes(label, claims, o.now, o.skew);
        Map<String, Object> mandate = delegateMandate(claims, label);
        checkTimes(label + " mandate", mandate, o.now, o.skew);
        boolean hasCnf = Js.isObj(mandate.get("cnf"));
        if (o.terminal && hasCnf) throw new Ap2Error(label + ": a terminal hop must not carry cnf");
        if (!o.terminal && !hasCnf) throw new Ap2Error(label + ": an intermediate hop requires cnf");
        if (o.terminal) {
            if (o.expectedAudience == null || !o.expectedAudience.equals(claims.get("aud"))) throw new Ap2Error(label + ": aud mismatch");
            if (o.expectedNonce == null || !o.expectedNonce.equals(claims.get("nonce"))) throw new Ap2Error(label + ": nonce mismatch");
        }
        return new VerifiedHop(-1, o.terminal ? "terminal" : "intermediate", hop, claims, mandate);
    }

    private static String message(RuntimeException e) { return String.valueOf(e.getMessage()); }

    private static double nowOf(Double now) { return now != null ? now : Math.floor(System.currentTimeMillis() / 1000.0); }

    /** Verify a whole chain: root signature, then every hop in order. Never throws; reports the reason. */
    public static ChainResult verifyDelegationChain(String token, VerifyChainOptions o) {
        try {
            if (o.expectedAudience == null || o.expectedAudience.isEmpty() || o.expectedNonce == null || o.expectedNonce.isEmpty()) {
                throw new Ap2Error("verify: expectedAudience and expectedNonce are required");
            }
            double now = nowOf(o.now);
            double skew = o.clockSkewSeconds != null ? o.clockSkewSeconds : 60;
            List<SdJwtHop> segments = new ArrayList<>();
            for (String s : splitChain(token)) segments.add(Sdjwt.parseSdJwtHop(s));
            SdJwtHop root = segments.get(0);
            if (root.header.containsKey("crit")) throw new Ap2Error("root: crit headers are not supported");
            Map<String, Object> issuerKey = o.resolveIssuerKey.apply(root.header);
            if (issuerKey == null) throw new Ap2Error("root: no issuer key for this header");
            if (!Sdjwt.verifyHopSignature(root, issuerKey)) throw new Ap2Error("root: signature does not verify under the issuer key");
            Map<String, Object> rootClaims = Sdjwt.processDisclosures(root.payload, root.disclosures, root.sdAlg);
            checkTimes("root", rootClaims, now, skew);
            Map<String, Object> rootMandate = delegateMandate(rootClaims, "root");
            checkTimes("root mandate", rootMandate, now, skew);
            List<VerifiedHop> hops = new ArrayList<>();
            hops.add(new VerifiedHop(0, "root", root, rootClaims, rootMandate));
            for (int i = 1; i < segments.size(); i++) {
                VerifiedHop v = verifyKbHop(segments.get(i), hops.get(i - 1), new KbOptions(i == segments.size() - 1, o.expectedAudience, o.expectedNonce, now, skew), "hop " + i);
                v.index = i;
                hops.add(v);
            }
            ChainResult r = new ChainResult();
            r.ok = true;
            r.hops = hops;
            return r;
        } catch (RuntimeException e) {
            return ChainResult.fail(message(e));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // typed chains
    // ---------------------------------------------------------------------------------------------

    private static VerifiedHop[] pair(ChainResult r) {
        if (r.hops.size() != 2) throw new Ap2Error("expected an open mandate followed by one closed mandate, got " + r.hops.size() + " hop(s)");
        return new VerifiedHop[] {r.hops.get(0), r.hops.get(1)};
    }

    private static void requireOpenExpiry(Map<String, Object> m, String label) {
        if (!Js.isSafeInteger(m.get("exp"))) throw new Ap2Error(label + ": an open mandate must carry exp");
    }

    /** Options of {@link #verifyCheckoutChain}. */
    public static class VerifyCheckoutOptions extends VerifyChainOptions {
        /** Resolve the merchant's key for the {@code checkout_jwt} signature; return null to refuse. */
        public Function<Map<String, Object>, Map<String, Object>> resolveMerchantKey;
    }

    /** Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints. */
    public static ChainResult verifyCheckoutChain(String token, VerifyCheckoutOptions o) {
        ChainResult r = verifyDelegationChain(token, o);
        if (!r.ok) return r;
        try {
            VerifiedHop[] p = pair(r);
            Map<String, Object> open = p[0].mandate, closed = p[1].mandate;
            List<String> op = Mandates.openCheckoutMandateProblems(open);
            if (!op.isEmpty()) throw new Ap2Error("open checkout mandate: " + String.join("; ", op));
            requireOpenExpiry(open, "open checkout mandate");
            List<String> cp = Mandates.checkoutMandateProblems(closed);
            if (!cp.isEmpty()) throw new Ap2Error("closed checkout mandate: " + String.join("; ", cp));
            String alg = p[1].hop.sdAlg;
            String checkoutJwt = (String) closed.get("checkout_jwt");
            if (!Sdjwt.sdDigest(checkoutJwt, alg).equals(closed.get("checkout_hash"))) throw new Ap2Error("checkout_hash does not match checkout_jwt");
            Sdjwt.ParsedJwt jwt = Sdjwt.parseJwt(checkoutJwt, "checkout_jwt");
            Map<String, Object> key = o.resolveMerchantKey.apply(jwt.header);
            if (key == null) throw new Ap2Error("checkout_jwt: no merchant key for this header");
            if (!Sdjwt.verifyJwtEs256(jwt, key)) throw new Ap2Error("checkout_jwt: merchant signature does not verify");
            Map<String, Object> checkout = Constraints.projectCheckout(jwt.payload);
            List<String> violations = Constraints.checkCheckoutConstraints(open, checkout);
            if (!violations.isEmpty()) {
                ChainResult f = ChainResult.fail("open checkout constraints violated: " + String.join("; ", violations));
                f.violations = violations;
                return f;
            }
            ChainResult ok = new ChainResult();
            ok.ok = true;
            ok.open = open;
            ok.closed = closed;
            ok.checkoutJwt = checkoutJwt;
            ok.checkout = checkout;
            ok.openHash = Sdjwt.sdHashOf(p[0].hop);
            ok.hops = r.hops;
            return ok;
        } catch (RuntimeException e) {
            return ChainResult.fail(message(e));
        }
    }

    /** Options of {@link #verifyPaymentChain}. */
    public static class VerifyPaymentOptions extends VerifyChainOptions {
        /** {@code sd_hash} of the open checkout mandate (from {@code verifyCheckoutChain().openHash}); checked against {@code payment.reference}. */
        public String openCheckoutHash;
        /** Usage state under this open mandate (needed for {@code payment.budget} and recurrence). */
        public Map<String, Object> context;
        /** The {@code checkout_hash} this payment must settle (from the closed checkout mandate). */
        public String expectedTransactionId;
    }

    /** Verify an open+closed payment chain and every open payment constraint. */
    public static ChainResult verifyPaymentChain(String token, VerifyPaymentOptions o) {
        ChainResult r = verifyDelegationChain(token, o);
        if (!r.ok) return r;
        try {
            VerifiedHop[] p = pair(r);
            Map<String, Object> open = p[0].mandate, closed = p[1].mandate;
            List<String> op = Mandates.openPaymentMandateProblems(open);
            if (!op.isEmpty()) throw new Ap2Error("open payment mandate: " + String.join("; ", op));
            requireOpenExpiry(open, "open payment mandate");
            List<String> cp = Mandates.paymentMandateProblems(closed);
            if (!cp.isEmpty()) throw new Ap2Error("closed payment mandate: " + String.join("; ", cp));
            if (o.expectedTransactionId != null && !o.expectedTransactionId.equals(closed.get("transaction_id"))) throw new Ap2Error("transaction_id does not match the checkout being settled");
            List<String> violations = Constraints.checkPaymentConstraints(open, closed, new Constraints.PaymentCheckOptions(o.openCheckoutHash, o.context, nowOf(o.now)));
            if (!violations.isEmpty()) {
                ChainResult f = ChainResult.fail("open payment constraints violated: " + String.join("; ", violations));
                f.violations = violations;
                return f;
            }
            ChainResult ok = new ChainResult();
            ok.ok = true;
            ok.open = open;
            ok.closed = closed;
            ok.openHash = Sdjwt.sdHashOf(p[0].hop);
            ok.hops = r.hops;
            return ok;
        } catch (RuntimeException e) {
            return ChainResult.fail(message(e));
        }
    }

    /** The audience and nonce a verifier expects of one chain's terminal hop. */
    public static final class Expect {
        public String expectedAudience;
        public String expectedNonce;

        public Expect(String expectedAudience, String expectedNonce) {
            this.expectedAudience = expectedAudience;
            this.expectedNonce = expectedNonce;
        }
    }

    /** Options of {@link #verifyPurchase}. */
    public static class VerifyPurchaseOptions {
        public Function<Map<String, Object>, Map<String, Object>> resolveIssuerKey;
        public Function<Map<String, Object>, Map<String, Object>> resolveMerchantKey;
        public Expect checkout;
        public Expect payment;
        public Map<String, Object> context;
        public Double now;
        public Double clockSkewSeconds;
    }

    /** A verified purchase: the checkout chain and the payment chain bound to it; or a failure {@code reason}. */
    public static final class PurchaseResult {
        public boolean ok;
        public String reason;
        public ChainResult checkout;
        public ChainResult payment;

        public static PurchaseResult fail(String reason) {
            PurchaseResult r = new PurchaseResult();
            r.reason = reason;
            return r;
        }
    }

    /**
     * Verify a complete purchase: the checkout chain, then the payment chain bound to it (the payment's
     * {@code payment.reference} is the open checkout hash; its {@code transaction_id} is the closed checkout's
     * {@code checkout_hash}), and that the payment settles what the merchant quoted (payee, currency, total).
     */
    public static PurchaseResult verifyPurchase(String checkoutToken, String paymentToken, VerifyPurchaseOptions o) {
        VerifyCheckoutOptions co = new VerifyCheckoutOptions();
        co.resolveIssuerKey = o.resolveIssuerKey;
        co.now = o.now;
        co.clockSkewSeconds = o.clockSkewSeconds;
        co.expectedAudience = o.checkout.expectedAudience;
        co.expectedNonce = o.checkout.expectedNonce;
        co.resolveMerchantKey = o.resolveMerchantKey;
        ChainResult c = verifyCheckoutChain(checkoutToken, co);
        if (!c.ok) return PurchaseResult.fail("checkout: " + c.reason);
        VerifyPaymentOptions po = new VerifyPaymentOptions();
        po.resolveIssuerKey = o.resolveIssuerKey;
        po.now = o.now;
        po.clockSkewSeconds = o.clockSkewSeconds;
        po.expectedAudience = o.payment.expectedAudience;
        po.expectedNonce = o.payment.expectedNonce;
        po.openCheckoutHash = c.openHash;
        po.expectedTransactionId = (String) c.closed.get("checkout_hash");
        po.context = o.context;
        ChainResult pay = verifyPaymentChain(paymentToken, po);
        if (!pay.ok) return PurchaseResult.fail("payment: " + pay.reason);
        Object total = Constraints.checkoutTotal(c.checkout);
        if (total == null) return PurchaseResult.fail("checkout: needs exactly one total entry");
        Object amt = pay.closed.get("payment_amount");
        if (!Js.sEq(Js.get(amt, "currency"), c.checkout.get("currency"))) return PurchaseResult.fail("payment currency differs from the checkout currency");
        if (!Js.sEq(Js.get(amt, "amount"), total)) return PurchaseResult.fail("payment amount " + Js.str(Js.get(amt, "amount")) + " differs from the checkout total " + Js.str(total));
        if (!c.checkout.containsKey("merchant")) return PurchaseResult.fail("checkout: no merchant to compare the payee with");
        if (!Js.sEq(Js.get(c.checkout.get("merchant"), "id"), Js.get(pay.closed.get("payee"), "id"))) return PurchaseResult.fail("payee differs from the checkout merchant");
        PurchaseResult ok = new PurchaseResult();
        ok.ok = true;
        ok.checkout = c;
        ok.payment = pay;
        return ok;
    }
}
