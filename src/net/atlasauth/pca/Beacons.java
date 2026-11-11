package net.atlasauth.pca;

import java.util.List;
import java.util.Map;

/**
 * Dead-man liveness beacons v2 (the reference's {@code beacons.ts}): an issuer signs short-lived beacons; authority is live only while a valid beacon
 * covers the current moment. {@link #verify} checks the signature, the pinned issuer, the instance and scope binding, the hard maximum validity and the
 * freshness window; {@link #ref} is what a PCActn commits in {@code freshness.beacon_ref}. Total.
 */
public final class Beacons {
    private Beacons() {}

    public static final String LIVENESS_DOMAIN = "atlas-pca/beacon/v2\u0000";
    public static final String GLOBAL_SCOPE = "*";
    public static final long EPOCH_MS = 60_000L;
    public static final long MAX_VALIDITY_MS = 60L * 60_000L;
    public static final long CLOCK_SKEW_MS = 30_000L;

    private static boolean integral(Object o) {
        Double d = Caveats.fin(o);
        return d != null && d == Math.rint(d) && !Double.isInfinite(d);
    }

    /** The reason a beacon is refused, or null when it verifies for ({@code instance}, {@code scope}, {@code now}). {@code scope} null skips the scope check. */
    @SuppressWarnings("unchecked")
    public static String verify(Object beacon, List<String> issuers, long now, String instance, String scope, Map<String, Object> pqPins) {
        try {
            if (!(beacon instanceof Map)) return "malformed beacon";
            Map<String, Object> b = (Map<String, Object>) beacon;
            Object v = b.get("v");
            boolean algPresent = b.containsKey("alg");
            if (!(IntentJs.isInt(v) && IntentJs.num(v) == 2) || Pq.resolveSigAlg(b.get("alg"), algPresent) == null) return "malformed beacon";
            if (!(b.get("instance") instanceof String) || !b.get("instance").equals(instance)) return "wrong instance";
            if (!(b.get("issuer") instanceof String) || !issuers.contains(b.get("issuer"))) return "issuer not pinned";
            Map<String, Object> base = Ledger.pick(b, "v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer");
            if (base == null) return "malformed beacon";
            byte[] msg = Pca.concat(LIVENESS_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                IntentJs.canonBytes(IntentJs.bindSuiteFields(base, b.get("alg"), algPresent, b.get("pq_pk"), b.containsKey("pq_pk"))));
            if (!IntentJs.verifyPinnedSuite(b.get("alg"), algPresent, (String) b.get("issuer"), b.get("pq_pk"), msg, b.get("sig"), b.get("pq_sig"), pqPins)) return "bad signature";
            for (String k : new String[] {"epoch", "seq", "issued_at", "not_after"}) if (!integral(b.get(k))) return "malformed window";
            double seq = Caveats.fin(b.get("seq")), issued = Caveats.fin(b.get("issued_at")), notAfter = Caveats.fin(b.get("not_after")), epoch = Caveats.fin(b.get("epoch"));
            if (seq < 0) return "malformed window";
            if (notAfter <= issued || notAfter - issued > MAX_VALIDITY_MS) return "validity exceeds the hard maximum";
            if (epoch != Math.floor(issued / EPOCH_MS)) return "epoch does not match issued_at";
            if (now + CLOCK_SKEW_MS < issued) return "not yet valid";
            if (now > notAfter) return "expired";
            if (scope != null && !GLOBAL_SCOPE.equals(b.get("scope")) && !scope.equals(b.get("scope"))) return "scope not covered";
            return null;
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return "malformed beacon";
        }
    }

    /** The stable reference to a beacon: base64url SHA-256 of its canonical form. */
    public static String ref(Map<String, Object> beacon) {
        return Pca.b64(AttestCommon.sha256Sum(IntentJs.canonBytes(beacon)));
    }
}
