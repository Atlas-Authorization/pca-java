package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.fhe.Fhe;
import net.atlasauth.pca.fhe.Origin;
import org.junit.jupiter.api.Test;

/** Differential tests of the pure parts of pca-fhe (quantization, gate policy, signed-claim and verdict-attestation layer). */
class FheDiffTest {
    private static final String MOD = "ref-fhe";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return o == null ? null : (Map<String, Object>) o; }

    private static List<Object> doubles(double[] d) { List<Object> o = new ArrayList<>(); for (double x : d) o.add(x); return o; }

    private static byte[] seed(Object o) { return Keys.unb64u((String) o); }

    private static Map<String, Object> m(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    @Test void quantization() throws Exception {
        OracleCases.each(MOD, "transformedInputs", a -> doubles(Fhe.transformedInputs(map(a.get(0)))));
        OracleCases.each(MOD, "quantizeRiskInputs", a -> doubles(a.size() == 1 ? Fhe.quantizeRiskInputs(map(a.get(0))) : Fhe.quantizeRiskInputs(map(a.get(0)), a.get(1))));
        OracleCases.each(MOD, "weightVector", a -> doubles(Fhe.weightVector(map(a.get(0)))));
        OracleCases.each(MOD, "fheRiskPolicy", a -> a.size() == 2 ? Fhe.fheRiskPolicy(map(a.get(0)), a.get(1)) : Fhe.fheRiskPolicy(map(a.get(0)), a.get(1), a.get(2)));
        OracleCases.each(MOD, "plaintextVerdict", a -> Fhe.plaintextVerdict(map(a.get(0)), map(a.get(1)), a.get(2)));
        OracleCases.each(MOD, "fromActn", a -> doubles(Fhe.transformedInputs(Fhe.riskInputsFromPCActn(map(a.get(0))))));
        OracleCases.each(MOD, "binding", a -> Fhe.bindingFromPCActn(map(a.get(0))));
    }

    @Test void signedClaims() throws Exception {
        OracleCases.each(MOD, "sign", a -> Origin.signRiskClaim(map(a.get(0)), seed(a.get(1)), (String) a.get(2), Keys.unb64u((String) map(a.get(3)).get("$bytes"))));
        OracleCases.each(MOD, "claimDigest", a -> Origin.signedClaimDigest(a.get(0)));
        OracleCases.each(MOD, "verifyClaim", a -> {
            Map<String, Object> e = map(a.get(1));
            Origin.ClaimExpectations exp = new Origin.ClaimExpectations();
            List<String> signers = new ArrayList<>();
            for (Object s : (List<?>) e.get("trustedSigners")) signers.add((String) s);
            exp.trustedSigners = signers;
            exp.context = (String) e.get("context");
            exp.binding = e.get("binding");
            exp.policy = e.get("policy");
            java.util.Set<String> used = new java.util.HashSet<>();
            for (Object u : (List<?>) e.get("used")) used.add((String) u);
            int max = (int) Double.parseDouble(e.get("max").toString());
            exp.nonces = k -> { if (used.contains(k) || used.size() >= max) return false; used.add(k); return true; };
            Origin.ClaimCheck r = Origin.verifySignedRiskClaim(a.get(0), exp);
            return r.ok() ? m("ok", true, "claim", r.claim(), "digest", r.digest()) : m("ok", false, "reason", r.reason());
        });
        OracleCases.each(MOD, "nonceGuard", a -> {
            Origin.NonceGuard g = Origin.memoryNonceGuard((int) Double.parseDouble(a.get(0).toString()));
            List<Object> out = new ArrayList<>();
            for (Object k : (List<?>) a.get(1)) out.add(g.claim((String) k));
            return out;
        });
    }

    @Test void verdictAttestations() throws Exception {
        OracleCases.each(MOD, "attest", a -> Origin.attestVerdict(seed(a.get(0)), map(a.get(1)), map(a.get(2)), Boolean.TRUE.equals(a.get(3))));
        OracleCases.each(MOD, "verifyAttest", a -> {
            Map<String, Object> e = map(a.get(1));
            List<String> holders = new ArrayList<>();
            for (Object h : (List<?>) e.get("trustedHolders")) holders.add((String) h);
            Origin.AttestationCheck r = Origin.verifyVerdictAttestation(a.get(0), holders, (String) e.get("claimDigest"), map(e.get("gate")));
            return r.ok() ? m("ok", true, "admit", r.admit()) : m("ok", false, "reason", r.reason());
        });
    }
}
