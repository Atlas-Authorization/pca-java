package net.atlasauth.pca;

import java.util.LinkedHashMap;
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
        return Pca.b64(AttestCommon.sha256Sum(IntentJs.canonBytes(IntentJs.normalize(beacon))));
    }

    /**
     * Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher {@code seq} (same instance, scope and issuer). Returns
     * null when {@code next} may be accepted, else the reason. {@code prev} is the beacon accepted before (null: none); a non-object or
     * non-integer-seq {@code next} is refused as malformed, never an error.
     */
    public static String accept(Object prev, Object next) {
        if (!(next instanceof Map) || !IntentJs.isNonNeg(((Map<?, ?>) next).get("seq"))) return "malformed beacon";
        double seq = IntentJs.num(((Map<?, ?>) next).get("seq"));
        if (prev == null) return null;
        boolean has = prev instanceof Map && ((Map<?, ?>) prev).containsKey("seq");
        Object prevSeq = prev instanceof Map ? ((Map<?, ?>) prev).get("seq") : null;
        // the reference compares with JavaScript's relational coercion (a string "0" is 0, a missing seq is NaN) and prints the member as it is
        if (seq > Actions.jsNumber(prevSeq, has)) return null;
        return "replayed beacon: seq " + AttestCommon.jsNumString(seq) + " <= " + IntentRevocation.jsText(prevSeq, has);
    }

    /** Frozen unless at least one beacon verifies for ({@code instance}, {@code scope}, {@code now}). Absence is a freeze. */
    public static boolean isFrozen(List<?> beacons, List<String> issuers, long now, String instance, String scope, Map<String, Object> pqPins) {
        if (beacons != null) for (Object b : beacons) if (verify(b, issuers, now, instance, scope, pqPins) == null) return false;
        return true;
    }

    // ---- the reference's surface over decoded JSON ----

    public static final long BEACON_EPOCH_MS = EPOCH_MS;
    public static final long BEACON_MAX_VALIDITY_MS = MAX_VALIDITY_MS;
    public static final long BEACON_CLOCK_SKEW_MS = CLOCK_SKEW_MS;

    private static Map<String, Object> verdict(String reason) { return reason == null ? Issue.obj("ok", true) : Issue.obj("ok", false, "reason", reason); }

    private static Map<String, Object> livenessBody(Map<String, Object> b) {
        Map<String, Object> base = Ledger.pick(b, "v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer");
        if (base == null) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        return IntentJs.bindSuiteFields(base, b.get("alg"), b.containsKey("alg"), b.get("pq_pk"), b.containsKey("pq_pk"));
    }

    /** The stable reference to a beacon, what a PCActn commits in {@code freshness.beacon_ref}: base64url(sha256(canonical JSON of the beacon)). */
    public static String beaconRef(Map<String, Object> beacon) { return Pca.hashCanonical(new java.util.LinkedHashMap<>(beacon)); }

    /**
     * The exact bytes the issuer signs: {@code "atlas-pca/beacon/v2\0" || canonical JSON of {v, instance, scope, epoch, seq, issued_at,
     * not_after, issuer}}; for a non-ed25519 suite {@code alg} and {@code pq_pk} are signed in too. Members the body does not name are
     * ignored. Throws on a missing member or a value with no canonical form.
     */
    public static byte[] livenessBeaconMessage(Map<String, Object> body) {
        return Pca.concat(LIVENESS_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8), IntentJs.canonBytes(IntentJs.normalize(livenessBody(body))));
    }

    private static boolean wholeNumber(Object o) { Double d = IntentJs.num(o); return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d); }

    /**
     * Issue a beacon. {@code args}: {@code issuerSecret} (byte[]), {@code instance}, {@code scope} (absent or null: {@code "*"}), {@code seq} (a
     * non-negative integer), {@code issuedAt} (an integer), {@code validityMs} (absent or null: 5 minutes; an integer in (0, 1 hour]) and an
     * optional {@code suite} ({@link Pq.SignerSuiteOpts}). Throws on any violation, or on a member with no canonical form.
     */
    public static Map<String, Object> issueLivenessBeacon(Map<String, Object> args) {
        Object vm = args.get("validityMs");
        Object validity = vm == null ? IntentJs.ofLong(5 * EPOCH_MS) : vm;
        Object seq = args.get("seq"), issuedAt = args.get("issuedAt");
        if (!wholeNumber(seq) || IntentJs.num(seq) < 0) throw new IllegalArgumentException("issueLivenessBeacon: seq must be a non-negative integer");
        if (!wholeNumber(issuedAt) || IntentJs.num(issuedAt) < 0) throw new IllegalArgumentException("issueLivenessBeacon: issuedAt must be an integer");
        double v = wholeNumber(validity) ? IntentJs.num(validity) : Double.NaN;
        if (!(v > 0 && v <= MAX_VALIDITY_MS)) throw new IllegalArgumentException("issueLivenessBeacon: validity must be in (0, " + MAX_VALIDITY_MS + "] ms");
        Pq.SignerSuiteOpts suite = (Pq.SignerSuiteOpts) args.get("suite");
        String alg = suite == null ? null : suite.alg;
        byte[] secret = (byte[]) args.get("issuerSecret");
        Pq.SuiteSecretKeys keys = Pq.suiteKeysOf(secret, suite);
        String pqPk = Pq.suitePqPublicKey(alg, keys);
        if (!args.containsKey("instance")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        double issued = IntentJs.num(issuedAt);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", IntentJs.ofLong(2));
        body.put("instance", args.get("instance"));
        body.put("scope", args.get("scope") != null ? args.get("scope") : GLOBAL_SCOPE);
        body.put("epoch", StoreJs.num(Math.floor(issued / EPOCH_MS)));
        body.put("seq", seq);
        body.put("issued_at", issuedAt);
        body.put("not_after", StoreJs.num(issued + v));
        body.put("issuer", Keys.edFromSeed(secret).id());
        Map<String, Object> bound = IntentJs.bindSuiteFields(new LinkedHashMap<>(), alg, alg != null, pqPk, pqPk != null);
        body.putAll(bound);
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, keys, livenessBeaconMessage(body));
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("sig", f.sig);
        if (f.alg != null) out.put("alg", f.alg);
        if (f.pqPk != null) out.put("pq_pk", f.pqPk);
        if (f.pqSig != null) out.put("pq_sig", f.pqSig);
        return out;
    }

    private static Object member(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /**
     * Verify a beacon against {@code check = {issuers, now, instance, scope?, pqPins?}}: {@code {ok: true}} or {@code {ok: false, reason}}, never
     * a throw. In order: the shape and suite ("malformed beacon"); the instance; the pinned issuer; the signature (a PQ or hybrid beacon verifies
     * under a verifier-pinned key only); integer, non-negative window fields; validity in (0, 1 hour]; the epoch; not-yet-valid with 30 s skew;
     * expiry; and, when the check names a scope, that the beacon is global or for that scope.
     */
    public static Map<String, Object> verifyLivenessBeacon(Object beacon, Map<String, Object> check) {
        try {
            if (!Zk.truthy(beacon)) return verdict("malformed beacon");
            Map<String, Object> b = beacon instanceof Map ? StoreJs.map(beacon) : new LinkedHashMap<>();
            if (!(IntentJs.isInt(b.get("v")) && IntentJs.num(b.get("v")) == 2) || Pq.resolveSigAlg(b.get("alg"), b.containsKey("alg")) == null) return verdict("malformed beacon");
            if (!Ledger.jsEq(b.get("instance"), member(check, "instance"))) return verdict("wrong instance");
            Object issuers = member(check, "issuers");
            if (issuers == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'includes')");
            boolean pinned;
            if (issuers instanceof List) pinned = ((List<?>) issuers).contains(b.get("issuer")) && b.get("issuer") != null;
            else if (issuers instanceof String) pinned = ((String) issuers).contains(IntentRevocation.jsText(b.get("issuer"), b.containsKey("issuer")));
            else throw new IllegalArgumentException("issuers.includes is not a function");
            if (!pinned) return verdict("issuer not pinned");
            boolean algPresent = b.containsKey("alg");
            if (!IntentJs.verifyPinnedSuite(b.get("alg"), algPresent, (String) b.get("issuer"), b.get("pq_pk"), livenessBeaconMessage(b), b.get("sig"), b.get("pq_sig"),
                StoreJs.map(member(check, "pqPins")))) return verdict("bad signature");
            for (String k : new String[] {"epoch", "seq", "issued_at", "not_after"}) if (!wholeNumber(b.get(k))) return verdict("malformed window");
            double seq = IntentJs.num(b.get("seq")), issued = IntentJs.num(b.get("issued_at")), notAfter = IntentJs.num(b.get("not_after")), epoch = IntentJs.num(b.get("epoch"));
            if (seq < 0) return verdict("malformed window");
            if (notAfter <= issued || notAfter - issued > MAX_VALIDITY_MS) return verdict("validity exceeds the hard maximum");
            if (epoch != Math.floor(issued / EPOCH_MS)) return verdict("epoch does not match issued_at");
            Object nowO = member(check, "now");
            boolean nowHas = check != null && check.containsKey("now");
            // `now + skew` is a string when now is a string, which the comparison then reads as a number
            double plus = nowO instanceof String ? Actions.jsNumber(nowO + AttestCommon.jsNumString(CLOCK_SKEW_MS), true) : Actions.jsNumber(nowO, nowHas) + CLOCK_SKEW_MS;
            if (plus < issued) return verdict("not yet valid");
            if (Actions.jsNumber(nowO, nowHas) > notAfter) return verdict("expired");
            if (check != null && check.containsKey("scope") && !GLOBAL_SCOPE.equals(b.get("scope")) && !Ledger.jsEq(b.get("scope"), check.get("scope"))) return verdict("scope not covered");
            return verdict(null);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return verdict("malformed beacon");
        }
    }

    /** {@link #accept(Object, Object)} as the reference's verdict {@code {ok}} / {@code {ok: false, reason}}. */
    public static Map<String, Object> acceptBeacon(Object prev, Object next) { return verdict(accept(prev, next)); }

    /** True when NO beacon in the list verifies for the check (see {@link #verifyLivenessBeacon}). */
    public static boolean isFrozenLiveness(List<?> beacons, Map<String, Object> check) {
        for (Object b : beacons) if (Boolean.TRUE.equals(verifyLivenessBeacon(b, check).get("ok"))) return false;
        return true;
    }

    /** The store key of a beacon's sequence slot: per (instance, scope, issuer). */
    static String seqKey(Map<?, ?> b) {
        List<Object> id = new java.util.ArrayList<>();
        id.add(b.get("instance"));
        id.add(b.get("scope"));
        id.add(b.get("issuer"));
        return "beacon-seq/v1/" + Json.canonicalize(id);
    }

    /** Durable replay protection over {@code kv}. Throws on a null store. */
    public static Acceptor createBeaconAcceptor(AtomicKv kv) { return new Acceptor(kv); }

    /** Durable replay protection for beacons: {@link #accept} against the highest {@code seq} already taken, in an {@link AtomicKv}. */
    public static final class Acceptor {
        private final AtomicKv kv;

        public Acceptor(AtomicKv kv) {
            if (kv == null) throw new IllegalArgumentException("Beacons.Acceptor: an AtomicKv is required");
            this.kv = kv;
        }

        /**
         * Verifies {@code beacon} (as {@link #verify}), then records its {@code seq} iff it is STRICTLY above the highest accepted for the
         * same (instance, scope, issuer) under one atomic update. Null when the beacon is fresh, else the reason: a failed verification,
         * {@code replayed beacon: seq N <= M} (nothing recorded), or {@code beacon state unavailable} when the store cannot decide (it throws or
         * holds a malformed value): FAIL CLOSED. Never throws.
         */
        /** {@link #accept(Object, List, long, String, String, Map)} over a decoded check {@code {issuers, now, instance, scope?, pqPins?}}: {@code {ok}} or {@code {ok: false, reason}}. */
        public Map<String, Object> accept(Object beacon, Map<String, Object> check) {
            Map<String, Object> v = verifyLivenessBeacon(beacon, check);
            if (!Boolean.TRUE.equals(v.get("ok"))) return v;
            Map<?, ?> b = (Map<?, ?>) beacon;
            double seq = IntentJs.num(b.get("seq"));
            Object[] replayOf = new Object[1];
            try {
                kv.update(seqKey(b), prev -> {
                    replayOf[0] = null;
                    if (prev != null && !IntentJs.isNonNeg(prev)) throw new IllegalStateException("beacon state is malformed"); // junk in the store: refuse
                    if (prev != null && !(seq > IntentJs.num(prev))) {
                        replayOf[0] = IntentJs.num(prev);
                        return null;
                    }
                    return b.get("seq");
                });
            } catch (RuntimeException e) {
                return verdict("beacon state unavailable");
            }
            return replayOf[0] == null ? verdict(null) : verdict("replayed beacon: seq " + AttestCommon.jsNumString(seq) + " <= " + AttestCommon.jsNumString((Double) replayOf[0]));
        }

        public String accept(Object beacon, List<String> issuers, long now, String instance, String scope, Map<String, Object> pqPins) {
            String bad = verify(beacon, issuers, now, instance, scope, pqPins);
            if (bad != null) return bad;
            Map<?, ?> b = (Map<?, ?>) beacon;
            long seq = IntentJs.lng(b.get("seq"));
            List<Object> id = new java.util.ArrayList<>();
            id.add(b.get("instance"));
            id.add(b.get("scope"));
            id.add(b.get("issuer"));
            Object[] replayOf = new Object[1];
            try {
                kv.update("beacon-seq/v1/" + Json.canonicalize(id), prev -> {
                    replayOf[0] = null;
                    if (prev != null && !IntentJs.isNonNeg(prev)) throw new IllegalStateException("beacon state is malformed"); // junk in the store: refuse
                    if (prev != null && !(seq > IntentJs.lng(prev))) {
                        replayOf[0] = IntentJs.lng(prev);
                        return null;
                    }
                    return StoreJs.num(seq);
                });
            } catch (RuntimeException e) {
                return "beacon state unavailable";
            }
            return replayOf[0] == null ? null : "replayed beacon: seq " + seq + " <= " + replayOf[0];
        }
    }
}
