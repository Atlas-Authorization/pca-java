package net.atlasauth.pca;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Test support for provenance by default: tests whose subject is another rule present every operation as coming straight from the
 * principal (a principal-direct bundle under the pinned harness mediator: Ed25519 seed = 32 bytes of 0x01, mediator
 * {@code conformance-harness}, kid {@code k1}), exactly as the TypeScript harnesses do, so the gate passes and the outcome is that of
 * the rule under test. The gate itself stays on.
 */
public final class ProvHarness {
    private ProvHarness() {}

    static final Keys.SuiteKey KEY;
    static {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 1);
        KEY = Keys.ed25519(Keys.edFromSeed(seed));
    }

    static ArgProvenance.Recorder recorder() { return new ArgProvenance.Recorder("conformance-harness", "k1", KEY, null, null); }

    /** The harness mediator pin. */
    public static final Map<String, Object> PIN = recorder().pin();

    /** The principal-direct bundle of one operation. */
    public static Map<String, Object> bundle(Authorize.Operation op) { return ArgProvenance.principalDirect(recorder(), op); }

    /** Gate options: pin the harness key and present a principal-direct bundle for the bound operation. */
    public static ArgProvenance.Options options() {
        return new ArgProvenance.Options().mediators(List.of(PIN)).bundle((pcactn, op) -> bundle(op));
    }
}
