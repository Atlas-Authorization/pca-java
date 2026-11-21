package net.atlasauth.pca;

import java.util.Map;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentProfile;
import org.junit.jupiter.api.Test;

class IntentProfileDiffTest {
    private static final String M = "ref-intent-profile";

    private static Map<String, Object> map(Object o) { return IntentOmega.obj(o); }

    @Test void signIntentProfile() throws Exception {
        OracleCases.each(M, "signIntentProfile", a -> IntentProfile.signIntentProfile(map(a.get(0)), Keys.unb64u((String) a.get(1))));
    }

    @Test void intentProfileShapeError() throws Exception {
        OracleCases.each(M, "intentProfileShapeError", a -> {
            boolean signed = a.size() < 2 || !(a.get(1) instanceof Map) || !Boolean.FALSE.equals(((Map<?, ?>) a.get(1)).get("signed"));
            return IntentProfile.intentProfileShapeError(a.get(0), signed);
        });
    }

    @Test void verifyIntentProfile() throws Exception { OracleCases.each(M, "verifyIntentProfile", a -> IntentProfile.verifyIntentProfile(a.get(0))); }

    @Test void intentProfileDigest() throws Exception { OracleCases.each(M, "intentProfileDigest", a -> IntentProfile.intentProfileDigest(a.get(0))); }

    @Test void verifyProfileSuccession() throws Exception { OracleCases.each(M, "verifyProfileSuccession", a -> IntentProfile.verifyProfileSuccession(a.get(0), a.get(1))); }

    @Test void profileApplies() throws Exception { OracleCases.each(M, "profileApplies", a -> IntentProfile.profileApplies(map(a.get(0)), map(a.get(1)))); }

    @Test void standingAdmits() throws Exception { OracleCases.each(M, "standingAdmits", a -> IntentProfile.standingAdmits(map(a.get(0)), map(a.get(1)), map(a.get(2)))); }

    @Test void standingPermits() throws Exception { OracleCases.each(M, "standingPermits", a -> IntentProfile.standingPermits(map(a.get(0)), map(a.get(1)), map(a.get(2)))); }

    @Test void profileVetoCells() throws Exception {
        OracleCases.each(M, "profileVetoCells", a -> IntentProfile.profileVetoCells(map(a.get(0)), IntentOmega.omegaFromJson(a.get(1))));
    }

    @Test void profileCeiling() throws Exception {
        OracleCases.each(M, "profileCeiling", a -> IntentProfile.profileCeiling(map(a.get(0)), map(a.get(1))).test(IntentOmega.verbSpaceFromJson(a.get(2)), IntentOmega.outcomeFromJson(a.get(3))));
    }

    @Test void profileUsable() throws Exception { OracleCases.each(M, "profileUsable", a -> IntentProfile.profileUsable(map(a.get(0)), map(a.get(1)))); }
}
