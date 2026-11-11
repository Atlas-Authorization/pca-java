package net.atlasauth.pca;

import java.util.Map;
import java.util.function.Function;

/**
 * The built-in hardware verifier of passport verification ({@link Passport.DefaultHardware}), used when no integrator
 * verifier is given. {@code evidence} returns the vendor evidence object for the passport's evidence document; a null
 * function means the document itself is the vendor evidence (and a function returning null means none).
 */
public final class DefaultHardware implements Passport.DefaultHardware {
    public final VendorVerifier verifier;
    public final Function<Map<String, Object>, Map<String, Object>> evidence;

    public DefaultHardware(VendorVerifier verifier, Function<Map<String, Object>, Map<String, Object>> evidence) {
        this.verifier = verifier;
        this.evidence = evidence;
    }

    /** The passport hardware seam bound to the clock nowMs. */
    @Override
    public Passport.Attest attest(long nowMs) {
        return (doc, expected) -> {
            Map<String, Object> ev = evidence == null ? doc : evidence.apply(doc);
            AttestationBinding b = new AttestationBinding(expected.holderPub, expected.grantRef, (double) expected.epoch, expected.nonce);
            HardwareResult r = verifier.verify(ev, b, nowMs);
            return new Passport.Attestation(r.ok, r.bound, r.measured);
        };
    }
}
