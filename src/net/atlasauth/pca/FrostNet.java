package net.atlasauth.pca;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.DoubleSupplier;
import java.util.function.Supplier;
import net.atlasauth.pca.Frost.FrostCommitResult;
import net.atlasauth.pca.Frost.FrostCommitment;
import net.atlasauth.pca.Frost.FrostNonces;
import net.atlasauth.pca.Frost.FrostParticipantShare;
import net.atlasauth.pca.Frost.FrostSignOpts;
import net.atlasauth.pca.Frost.FrostSignatureShare;
import net.atlasauth.pca.Frost.VerificationShare;
import net.atlasauth.pca.ratchet.EdwardsPoint;

/**
 * Multi-process network FROST for guardian custody: allow tokens (a policy authority's signed "allow this exact action under this group
 * key"), the signer proof of possession (rogue-key defense), the equivocation guard, the strict wire decoders, a single-share
 * {@link GuardianSignerService} and the {@link NetworkCoordinator} that drives a t-of-n session over {@link SignerTransport}s.
 * Wire values are JSON-shaped maps and lists (identifiers as numbers, bytes as base64url strings) exactly as the reference exchanges them;
 * a malformed value is a refusal, never a different outcome. Randomness (nonces, proof nonces, session ids) goes through a
 * {@code Supplier<byte[]>} of 32-byte draws, the system CSPRNG by default.
 */
public final class FrostNet {
    private FrostNet() {}

    public static final String ALLOW_TOKEN_TYP = "pca.frost.allow.v1";
    public static final String SIGNER_POP_DST = "pca.frost.signer-pop.v1";
    /** Largest signing set a signer or coordinator decodes: bounds the per-request interpolation work a hostile peer can demand. */
    public static final int MAX_FROST_SIGNING_SET = 256;

    static final Object UNDEFINED = new Object();
    private static final Supplier<byte[]> SECURE = Frost::randomScalarBytes;

    // ---- small JS-semantics helpers ----------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** Number.isSafeInteger(x) && x &gt; 0. */
    private static boolean posId(Object o) { return IntentJs.isSafeInteger(o) && IntentJs.num(o) > 0; }

    private static boolean numEq(Object a, Object b) {
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    private static boolean truthy(Object o) {
        if (o == null || o == UNDEFINED || Boolean.FALSE.equals(o)) return false;
        if (o instanceof String) return !((String) o).isEmpty();
        Double d = IntentJs.num(o);
        return d == null || !(d == 0.0 || Double.isNaN(d));
    }

    private static boolean isBytes32(Object o) { return o instanceof byte[] && ((byte[]) o).length == 32; }

    private static String b64u(Object bytes) {
        if (!(bytes instanceof byte[])) throw new IllegalArgumentException("radix2.encode input should be Uint8Array");
        return Pca.b64((byte[]) bytes);
    }

    private static byte[] sha256(byte[] m) { return Pca.sha(m); }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static String msg(Throwable e, String dflt) { return e.getMessage() != null ? e.getMessage() : dflt; }

    // ---- allow token ----------------------------------------------------------------------------------------------

    /** base64url(sha256(message)): the action digest an allow token authorizes. */
    public static String frostActionDigest(byte[] message) {
        if (message == null) throw new IllegalArgumentException("frostActionDigest: message must be bytes");
        return Pca.b64(sha256(message));
    }

    public static Map<String, Object> issueAllowToken(byte[] policySecretKey, Map<String, Object> opts) { return issueAllowToken(policySecretKey, opts, SECURE); }

    /**
     * Mint an allow token with the policy authority's Ed25519 secret key. {@code opts}: message (bytes) or frostActionDigest (string),
     * groupPublicKey (bytes), nonce, notBefore, expiresAt (a member that is present, even null, goes into the body).
     */
    public static Map<String, Object> issueAllowToken(byte[] policySecretKey, Map<String, Object> opts, Supplier<byte[]> random) {
        Object fad = opts.get("frostActionDigest"), message = opts.get("message");
        String digest = null;
        if (fad != null) digest = fad instanceof String ? (String) fad : AttestNvidia.jsString(fad);
        else if (truthy(message)) {
            if (!(message instanceof byte[])) throw new IllegalArgumentException("frostActionDigest: message must be bytes");
            digest = frostActionDigest((byte[]) message);
        }
        if (digest == null || digest.isEmpty()) throw new IllegalArgumentException("issueAllowToken: provide message or frostActionDigest");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("typ", ALLOW_TOKEN_TYP);
        body.put("action_digest", digest);
        body.put("group_pk", b64u(opts.get("groupPublicKey")));
        Object nonce = opts.get("nonce");
        body.put("nonce", nonce != null ? nonce : Pca.b64(random.get()));
        if (opts.containsKey("notBefore")) body.put("not_before", opts.get("notBefore"));
        if (opts.containsKey("expiresAt")) body.put("expires_at", opts.get("expiresAt"));
        Keys.EdKey key = Keys.edFromSeed(policySecretKey);
        String sig = Pca.b64(key.sign(Pca.canonBytes(body)));
        return mapOf("body", body, "authority", Pca.b64(key.pub), "sig", sig);
    }

    private static Map<String, Object> verdict(boolean ok, String reason) { return ok ? mapOf("ok", true) : mapOf("ok", false, "reason", reason); }

    /**
     * Verify an allow token against the key a signer was configured with (never {@code token.authority}). {@code expect}:
     * policyAuthorityPublicKey, groupPublicKey, message (bytes), now (number).
     */
    public static Map<String, Object> verifyAllowToken(Object token, Map<String, Object> expect) {
        try {
            if (!(token instanceof Map) && !(token instanceof List)) return verdict(false, "allow token missing or malformed");
            Map<String, Object> t = token instanceof Map ? obj(token) : new LinkedHashMap<>();
            Object bodyO = t.get("body");
            if (!(bodyO instanceof Map) && !(bodyO instanceof List)) return verdict(false, "allow token has no body");
            Map<String, Object> body = bodyO instanceof Map ? obj(bodyO) : new LinkedHashMap<>();
            if (!ALLOW_TOKEN_TYP.equals(body.get("typ"))) {
                return verdict(false, "allow token wrong typ (" + (body.containsKey("typ") ? AttestNvidia.jsString(body.get("typ")) : "undefined") + ")");
            }
            if (!(t.get("sig") instanceof String)) return verdict(false, "allow token missing signature");
            byte[] sigBytes = Pca.decodeB64uStrict(t.get("sig"), 64);
            if (sigBytes == null) return verdict(false, "allow token signature not canonical base64url");
            Object authority = expect.get("policyAuthorityPublicKey");
            if (!Pca.ed25519Strict(authority instanceof byte[] ? (byte[]) authority : null, Pca.canonBytes(body), sigBytes)) {
                return verdict(false, "allow token not signed by the trusted policy authority");
            }
            if (!b64u(expect.get("groupPublicKey")).equals(body.get("group_pk"))) return verdict(false, "allow token authorizes a different group key");
            Object m = expect.get("message");
            if (!frostActionDigest(m instanceof byte[] ? (byte[]) m : null).equals(body.get("action_digest"))) {
                return verdict(false, "allow token authorizes a different action digest");
            }
            Double now = IntentJs.num(expect.get("now"));
            if (now == null || now.isNaN() || now.isInfinite()) return verdict(false, "invalid verification time");
            if (body.containsKey("not_before") && lessThan(now, body.get("not_before"))) return verdict(false, "allow token not yet valid");
            if (body.containsKey("expires_at") && !lessThan(now, body.get("expires_at"))) return verdict(false, "allow token expired");
            return verdict(true, null);
        } catch (RuntimeException e) {
            return verdict(false, "allow token verification error (fail closed): " + msg(e, "unknown"));
        }
    }

    /** JavaScript {@code a < b} for a number and a JSON value (null reads as 0; a non-number is false). */
    private static boolean lessThan(double a, Object b) {
        Double d = b == null ? Double.valueOf(0) : IntentJs.num(b);
        return d != null && a < d;
    }

    // ---- signer proof of possession ----------------------------------------------------------------------------

    private static BigInteger popChallenge(byte[] group, long id, byte[] pk, byte[] r) {
        byte[] h = Frost.sha512(Frost.concat(Json.utf8(SIGNER_POP_DST), group, Frost.scalarToBytes(BigInteger.valueOf(id)), pk, r));
        BigInteger e = Frost.bytesToScalar(h);
        return e.signum() == 0 ? BigInteger.ONE : e;
    }

    public static Map<String, Object> createSignerPoP(Object identifier, Object share, Map<String, Object> opts) { return createSignerPoP(identifier, share, opts, SECURE); }

    /**
     * A signer's Schnorr proof of possession of its verification share, bound to a domain tag and the group key. {@code opts}:
     * groupPublicKey (32 bytes), nonce (optional fixed bytes, for vectors only; else drawn from {@code random}).
     */
    public static Map<String, Object> createSignerPoP(Object identifier, Object share, Map<String, Object> opts, Supplier<byte[]> random) {
        if (!posId(identifier)) throw new IllegalArgumentException("createSignerPoP: identifier must be a positive integer");
        if (!isBytes32(share)) throw new IllegalArgumentException("createSignerPoP: share must be 32 bytes");
        if (!isBytes32(opts.get("groupPublicKey"))) throw new IllegalArgumentException("createSignerPoP: groupPublicKey must be 32 bytes");
        byte[] group = (byte[]) opts.get("groupPublicKey");
        long id = IntentJs.lng(identifier);
        BigInteger x = Frost.bytesToScalar((byte[]) share);
        byte[] pk = Frost.mulBase(x).toBytes();
        Object nonce = opts.get("nonce");
        BigInteger k = nonce instanceof byte[] ? Frost.bytesToScalar((byte[]) nonce) : BigInteger.ZERO;
        while (k.signum() == 0) k = Frost.bytesToScalar(random.get());
        byte[] rBytes = Frost.mulBase(k).toBytes();
        BigInteger e = popChallenge(group, id, pk, rBytes);
        byte[] s = Frost.scalarToBytes(k.add(e.multiply(x)));
        return mapOf("identifier", identifier, "publicKey", Pca.b64(pk), "R", Pca.b64(rBytes), "s", Pca.b64(s));
    }

    /** Verify a signer proof of possession. Never throws: any malformed input or bad proof is false. */
    public static boolean verifySignerPoP(Object pop, Map<String, Object> expect) {
        try {
            Map<String, Object> p = obj(pop);
            if (p == null) return false;
            if (!posId(p.get("identifier"))) return false;
            Object g = expect.get("groupPublicKey");
            if (!isBytes32(g)) return false;
            byte[] pk = Pca.decodeB64uStrict(p.get("publicKey"), 32), rb = Pca.decodeB64uStrict(p.get("R"), 32), sb = Pca.decodeB64uStrict(p.get("s"), 32);
            if (pk == null || rb == null || sb == null) return false;
            EdwardsPoint pkPt = Frost.decodeSafePoint(pk), rPt = Frost.decodeSafePoint(rb);
            if (!Frost.isCanonicalScalar(sb)) return false;
            BigInteger s = Frost.bytesToScalar(sb), e = popChallenge((byte[]) g, IntentJs.lng(p.get("identifier")), pk, rb);
            return Frost.mulBase(s).sameAs(rPt.add(Frost.mulPoint(pkPt, e)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Thrown by {@link #enrollVerificationShares} when a signer's key has no valid proof of possession. */
    public static final class PoPError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final Object identifier;
        public PoPError(String message, Object identifier) { super(message); this.identifier = identifier; }
    }

    /**
     * The hardened enrollment surface: each enrollment ({identifier, publicKey (bytes), pop}) is accepted only with a valid proof of
     * possession binding its key under the group key. Returns [{identifier, publicKey}]; a rogue key throws {@link PoPError}.
     */
    public static List<Map<String, Object>> enrollVerificationShares(Object enrollments, Map<String, Object> expect) {
        if (!(enrollments instanceof List) || ((List<?>) enrollments).isEmpty()) throw new PoPError("enrollVerificationShares: no signer enrollments", null);
        if (!isBytes32(expect.get("groupPublicKey"))) throw new PoPError("enrollVerificationShares: groupPublicKey must be 32 bytes", null);
        List<Map<String, Object>> out = new ArrayList<>();
        Set<Double> seen = new HashSet<>();
        for (Object eo : (List<?>) enrollments) {
            Map<String, Object> e = obj(eo);
            if (e == null && eo instanceof List) e = new LinkedHashMap<>();
            if (e == null || !posId(e.get("identifier"))) throw new PoPError("enrollVerificationShares: enrollment with invalid identifier", null);
            Object id = e.get("identifier");
            if (!seen.add(IntentJs.num(id))) throw new PoPError("enrollVerificationShares: duplicate enrollment for signer " + AttestNvidia.jsString(id), id);
            if (!isBytes32(e.get("publicKey"))) throw new PoPError("enrollVerificationShares: signer " + AttestNvidia.jsString(id) + " verification share must be 32 bytes", id);
            Map<String, Object> pop = obj(e.get("pop"));
            if (pop == null || !numEq(pop.get("identifier"), id) || !Pca.b64((byte[]) e.get("publicKey")).equals(pop.get("publicKey"))) {
                throw new PoPError("enrollVerificationShares: signer " + AttestNvidia.jsString(id) + " missing or mismatched proof-of-possession (rogue key rejected)", id);
            }
            if (!verifySignerPoP(pop, expect)) {
                throw new PoPError("enrollVerificationShares: signer " + AttestNvidia.jsString(id) + " invalid proof-of-possession (rogue key rejected)", id);
            }
            out.add(mapOf("identifier", id, "publicKey", e.get("publicKey")));
        }
        return out;
    }

    // ---- equivocation guard ------------------------------------------------------------------------------------

    public static final class EquivocationError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String sessionId;
        public final long round, identifier;
        public final String previousDigest, offendingDigest;
        public EquivocationError(String sessionId, long round, long identifier, String previousDigest, String offendingDigest) {
            super("equivocation: signer " + identifier + " sent two different messages for session '" + sessionId + "' round " + round);
            this.sessionId = sessionId; this.round = round; this.identifier = identifier;
            this.previousDigest = previousDigest; this.offendingDigest = offendingDigest;
        }
    }

    /**
     * Records the first message per (session, round, signer) and refuses a second, different one; an identical repeat is idempotent.
     */
    public static final class EquivocationGuard {
        private final Map<String, String> seen = new HashMap<>();

        public synchronized void observe(Object sessionId, Object round, Object identifier, Object message) {
            if (!(sessionId instanceof String) || ((String) sessionId).isEmpty()) throw new IllegalArgumentException("EquivocationGuard: session_id must be a non-empty string");
            if (!IntentJs.isSafeInteger(round) || IntentJs.num(round) < 1) throw new IllegalArgumentException("EquivocationGuard: round must be a positive integer");
            if (!posId(identifier)) throw new IllegalArgumentException("EquivocationGuard: identifier must be a positive integer");
            long r = IntentJs.lng(round), id = IntentJs.lng(identifier);
            String key = sessionId + "\u0000" + r + "\u0000" + id;
            String digest = Pca.b64(sha256(Pca.canonBytes(message)));
            String prev = seen.get(key);
            if (prev == null) { seen.put(key, digest); return; }
            if (!prev.equals(digest)) throw new EquivocationError((String) sessionId, r, id, prev, digest);
        }

        /** Forget every binding of a session id. */
        public synchronized void forget(Object sessionId) {
            String prefix = AttestNvidia.jsString(sessionId) + "\u0000";
            seen.keySet().removeIf(k -> k.startsWith(prefix));
        }
    }

    // ---- wire decoders ---------------------------------------------------------------------------------------------

    static Map<String, Object> encodeCommitment(FrostCommitment c) {
        return mapOf("identifier", c.identifier, "hiding", Pca.b64(c.hiding), "binding", Pca.b64(c.binding));
    }

    /** Strict decode of one wire commitment; total: anything malformed is an IllegalArgumentException. */
    public static FrostCommitment decodeCommitment(Object wire) {
        Map<String, Object> w = obj(wire);
        if (w == null && wire instanceof List) w = new LinkedHashMap<>();
        if (w == null) throw new IllegalArgumentException("bad commitment");
        byte[] hiding = Pca.decodeB64uStrict(w.get("hiding"), 32), binding = Pca.decodeB64uStrict(w.get("binding"), 32);
        if (!posId(w.get("identifier"))) throw new IllegalArgumentException("bad commitment identifier");
        if (hiding == null || binding == null) throw new IllegalArgumentException("bad commitment point encoding");
        return new FrostCommitment(IntentJs.lng(w.get("identifier")), hiding, binding);
    }

    /** Strict decode of a list of wire commitments, bounded by {@link #MAX_FROST_SIGNING_SET}. */
    public static List<FrostCommitment> decodeCommitments(Object list) {
        if (!(list instanceof List)) throw new IllegalArgumentException("commitments must be a list");
        List<?> l = (List<?>) list;
        if (l.size() > MAX_FROST_SIGNING_SET) throw new IllegalArgumentException("commitments list exceeds the maximum signing set");
        List<FrostCommitment> out = new ArrayList<>();
        for (Object w : l) out.add(decodeCommitment(w));
        return out;
    }

    /** Strict decode of the signing set's public verification shares, bounded by {@link #MAX_FROST_SIGNING_SET}. */
    public static List<VerificationShare> decodeVerificationShares(Object list) {
        if (!(list instanceof List)) throw new IllegalArgumentException("verification_shares must be a list");
        List<?> l = (List<?>) list;
        if (l.size() > MAX_FROST_SIGNING_SET) throw new IllegalArgumentException("verification_shares list exceeds the maximum signing set");
        List<VerificationShare> out = new ArrayList<>();
        for (Object vo : l) {
            Map<String, Object> v = obj(vo);
            if (v == null && vo instanceof List) v = new LinkedHashMap<>();
            if (v == null) throw new IllegalArgumentException("bad verification share");
            byte[] pk = Pca.decodeB64uStrict(v.get("publicKey"), 32);
            if (!posId(v.get("identifier"))) throw new IllegalArgumentException("bad verification-share identifier");
            if (pk == null) throw new IllegalArgumentException("bad verification-share key encoding");
            out.add(new VerificationShare(IntentJs.lng(v.get("identifier")), pk));
        }
        return out;
    }

    // ---- durable nonce store -------------------------------------------------------------------------------------

    /** A round-1 nonce record: the secret nonces, the public commitments and the wall-clock ms at which the session opened. */
    public static final class NonceRecord {
        public final byte[] hiding, binding, hidingCommitment, bindingCommitment;
        public final double createdAt;
        public NonceRecord(byte[] hiding, byte[] binding, byte[] hidingCommitment, byte[] bindingCommitment, double createdAt) {
            this.hiding = hiding; this.binding = binding; this.hidingCommitment = hidingCommitment; this.bindingCommitment = bindingCommitment; this.createdAt = createdAt;
        }
        NonceRecord copy() { return new NonceRecord(hiding.clone(), binding.clone(), hidingCommitment.clone(), bindingCommitment.clone(), createdAt); }
    }

    /**
     * The contract of a durable round-1 nonce store: create is durable and refuses an existing id (live or spent); load returns the
     * live record or null; spend is atomic, durable, deletes the secrets and records the id as spent forever (a second spend throws);
     * isSpent is true for every spent id; every method throws on failure and the signer then refuses (fails closed).
     */
    public interface NonceStore {
        void create(String sessionId, NonceRecord record);
        NonceRecord load(String sessionId);
        void spend(String sessionId);
        void drop(String sessionId);
        boolean isSpent(String sessionId);
    }

    /** The reference store: correct, not durable (a restart loses it, which fails closed). */
    public static class MemoryNonceStore implements NonceStore {
        private final Map<String, NonceRecord> live = new HashMap<>();
        private final Set<String> spent = new HashSet<>();

        @Override public synchronized void create(String sessionId, NonceRecord record) {
            if (sessionId == null || sessionId.isEmpty()) throw new IllegalArgumentException("nonce-store: session id must be a non-empty string");
            if (live.containsKey(sessionId) || spent.contains(sessionId)) throw new IllegalStateException("nonce-store: session already exists");
            live.put(sessionId, record.copy());
        }

        @Override public synchronized NonceRecord load(String sessionId) {
            NonceRecord r = live.get(sessionId);
            return r == null ? null : r.copy();
        }

        @Override public synchronized void spend(String sessionId) {
            NonceRecord r = live.get(sessionId);
            if (r == null) throw new IllegalStateException("nonce-store: cannot spend a session that is not live");
            Arrays.fill(r.hiding, (byte) 0);
            Arrays.fill(r.binding, (byte) 0);
            live.remove(sessionId);
            spent.add(sessionId);
        }

        @Override public synchronized void drop(String sessionId) {
            NonceRecord r = live.get(sessionId);
            if (r != null) {
                Arrays.fill(r.hiding, (byte) 0);
                Arrays.fill(r.binding, (byte) 0);
                live.remove(sessionId);
            }
        }

        @Override public synchronized boolean isSpent(String sessionId) { return spent.contains(sessionId); }
    }

    /**
     * Conformance check for a {@link NonceStore}: {@code reopen} must return a store over the same durable state (a simulated
     * restart; the identity for the in-memory store). Throws {@link IllegalStateException} ("nonce-store contract: ...") on the first violation.
     */
    public static void assertNonceStoreContract(Supplier<NonceStore> make, java.util.function.UnaryOperator<NonceStore> reopen) {
        NonceStore s = make.get();
        must(s.load("a") == null && !s.isSpent("a"), "an unknown id is neither live nor spent");
        s.create("a", rec(1));
        final NonceStore s0 = s;
        must(throwsOn(() -> s0.create("a", rec(9))), "create must refuse an existing live id");
        s.create("b", rec(5));
        s = reopen.apply(s);
        NonceRecord got = s.load("a");
        must(got != null && got.hiding[0] == 1 && got.createdAt == 1, "a live record survives a restart");
        Arrays.fill(got.hiding, (byte) 0xee);
        must(s.load("a").hiding[0] == 1, "load returns a copy");
        s.spend("a");
        must(s.load("a") == null && s.isSpent("a"), "spend removes the secret and records the marker");
        final NonceStore s1 = s;
        must(throwsOn(() -> s1.spend("a")), "a second spend must throw");
        must(throwsOn(() -> s1.create("a", rec(2))), "create must refuse a spent id");
        must(throwsOn(() -> s1.spend("zzz")), "spend of an unknown id must throw");
        s = reopen.apply(s);
        must(s.isSpent("a") && s.load("a") == null, "a spent marker survives a restart");
        must(s.load("b") != null, "the other live record survives");
        s.drop("b");
        must(s.load("b") == null && !s.isSpent("b"), "drop removes a live record without marking it spent");
        s.drop("never-existed");
    }

    private static NonceRecord rec(int n) {
        byte[] a = new byte[32], b = new byte[32], c = new byte[32], d = new byte[32];
        Arrays.fill(a, (byte) n); Arrays.fill(b, (byte) (n + 1)); Arrays.fill(c, (byte) (n + 2)); Arrays.fill(d, (byte) (n + 3));
        return new NonceRecord(a, b, c, d, n);
    }

    private static void must(boolean ok, String what) { if (!ok) throw new IllegalStateException("nonce-store contract: " + what); }

    private static boolean throwsOn(Runnable r) {
        try { r.run(); } catch (RuntimeException e) { return true; }
        return false;
    }

    // ---- the guardian signer service --------------------------------------------------------------------------------

    private static final class Session {
        final FrostNonces nonces;
        final FrostCommitment commitment;
        final double createdAt;
        Session(FrostNonces nonces, FrostCommitment commitment, double createdAt) { this.nonces = nonces; this.commitment = commitment; this.createdAt = createdAt; }
    }

    /**
     * A single-share FROST signer: one instance, one trust domain. It keeps only its own secret nonces per session and releases a
     * signature share in round 2 iff it has live round-1 state, the request names its group key and the allow token verifies
     * independently against its configured policy key and binds to the exact message. A refusal keeps the nonces (an honest retry
     * works) unless a durable store is configured, where the session is marked spent before the share is computed.
     */
    public static final class GuardianSignerService {
        public final long identifier;
        private final byte[] verificationShare;
        private final byte[] share;
        private final byte[] groupPublicKey;
        private final long threshold;
        private final byte[] policyAuthorityPublicKey;
        private final Double sessionTtlMs;
        private final DoubleSupplier now;
        private final NonceStore store;
        private final Supplier<byte[]> random;
        private final Map<String, Session> sessions = new HashMap<>();
        private final Set<String> spent = new HashSet<>();
        private final Map<String, Object> pop;

        /**
         * {@code opts}: identifier, share (32 bytes), groupPublicKey (32), threshold (positive integer), policyAuthorityPublicKey (32),
         * sessionTtlMs (positive finite, optional), now (DoubleSupplier, default the system clock in ms), nonceStore (optional
         * {@link NonceStore}), random (Supplier of 32-byte draws, default the system CSPRNG).
         */
        @SuppressWarnings("unchecked")
        public GuardianSignerService(Map<String, Object> opts) {
            if (!posId(opts.get("identifier"))) throw new IllegalArgumentException("GuardianSignerService: identifier must be a positive integer");
            if (!isBytes32(opts.get("share"))) throw new IllegalArgumentException("GuardianSignerService: share must be 32 bytes");
            if (!isBytes32(opts.get("groupPublicKey"))) throw new IllegalArgumentException("GuardianSignerService: groupPublicKey must be 32 bytes");
            Object thr = opts.get("threshold");
            if (!IntentJs.isSafeInteger(thr) || IntentJs.num(thr) < 1) throw new IllegalArgumentException("GuardianSignerService: threshold must be a positive integer");
            if (!isBytes32(opts.get("policyAuthorityPublicKey"))) throw new IllegalArgumentException("GuardianSignerService: policyAuthorityPublicKey must be 32 bytes");
            Object ttl = opts.get("sessionTtlMs");
            if (ttl != null && (!IntentJs.isFinite(ttl) || IntentJs.num(ttl) <= 0)) throw new IllegalArgumentException("GuardianSignerService: sessionTtlMs must be a positive finite number");
            Object st = opts.get("nonceStore");
            if (st != null && !(st instanceof NonceStore)) throw new IllegalArgumentException("GuardianSignerService: nonceStore.spend must be a function");
            this.share = ((byte[]) opts.get("share")).clone();
            this.identifier = IntentJs.lng(opts.get("identifier"));
            this.groupPublicKey = ((byte[]) opts.get("groupPublicKey")).clone();
            this.threshold = IntentJs.lng(thr);
            this.policyAuthorityPublicKey = ((byte[]) opts.get("policyAuthorityPublicKey")).clone();
            this.sessionTtlMs = ttl == null ? null : IntentJs.num(ttl);
            this.now = opts.get("now") instanceof DoubleSupplier ? (DoubleSupplier) opts.get("now") : System::currentTimeMillis;
            this.store = (NonceStore) st;
            this.random = opts.get("random") instanceof Supplier ? (Supplier<byte[]>) opts.get("random") : SECURE;
            this.verificationShare = Frost.verifyingShare(this.share);
            this.pop = createSignerPoP(this.identifier, this.share, mapOf("groupPublicKey", this.groupPublicKey), this.random);
        }

        public byte[] verificationShare() { return verificationShare.clone(); }

        public Map<String, Object> proofOfPossession() { return pop; }

        /** A ready-to-enroll record (identifier, verification share, proof of possession) for {@link #enrollVerificationShares}. */
        public Map<String, Object> enrollment() { return mapOf("identifier", identifier, "publicKey", verificationShare.clone(), "pop", pop); }

        private Map<String, Object> fail(String reason) { return mapOf("ok", false, "identifier", identifier, "reason", reason); }

        /** Round 1: commit to a fresh nonce pair for the session; the secret nonces stay here. */
        public synchronized Map<String, Object> round1(Object reqO) {
            try {
                Map<String, Object> req = obj(reqO);
                if (req == null || !"pca.frost.round1.v1".equals(req.get("typ")) || !(req.get("session_id") instanceof String) || ((String) req.get("session_id")).isEmpty()) {
                    return fail("malformed round-1 request");
                }
                String sid = (String) req.get("session_id");
                if (spent.contains(sid) || (store != null && store.isSpent(sid))) return fail("session already signed");
                if (sessions.containsKey(sid) || (store != null && store.load(sid) != null)) return fail("duplicate round-1 for session");
                byte[] hr = random.get(), br = random.get();
                FrostCommitResult c = Frost.commit(new FrostParticipantShare(identifier, share, verificationShare), hr, br);
                double createdAt = now.getAsDouble();
                if (store != null) store.create(sid, new NonceRecord(c.hidingNonce, c.bindingNonce, c.commitment.hiding, c.commitment.binding, createdAt));
                sessions.put(sid, new Session(new FrostNonces(c.hidingNonce, c.bindingNonce), c.commitment, createdAt));
                return mapOf("ok", true, "identifier", identifier, "commitment", encodeCommitment(c.commitment), "pop", pop);
            } catch (RuntimeException e) {
                return fail(msg(e, "round-1 error"));
            }
        }

        private Map<String, Object> refuse(String reason) { return mapOf("ok", false, "identifier", identifier, "refused", true, "reason", reason); }

        /** Round 2: release a signature share iff the allow token verifies and the session has live round-1 state. */
        public synchronized Map<String, Object> round2(Object reqO) {
            try {
                Map<String, Object> req = obj(reqO);
                if (req == null || !"pca.frost.round2.v1".equals(req.get("typ")) || !(req.get("session_id") instanceof String)) return refuse("malformed round-2 request");
                String sid = (String) req.get("session_id");
                if (spent.contains(sid) || (store != null && store.isSpent(sid))) return refuse("session already signed (one-shot)");
                Session state = sessions.get(sid);
                if (state == null && store != null) {
                    NonceRecord rec = store.load(sid);
                    if (rec != null) {
                        state = new Session(new FrostNonces(rec.hiding, rec.binding), new FrostCommitment(identifier, rec.hidingCommitment, rec.bindingCommitment), rec.createdAt);
                        sessions.put(sid, state);
                    }
                }
                if (state == null) return refuse("no round-1 state for this session");

                double age = now.getAsDouble() - state.createdAt;
                if (sessionTtlMs != null && !(Double.isFinite(age) && age <= sessionTtlMs)) {
                    sessions.remove(sid);
                    if (store != null) store.drop(sid);
                    return refuse("session expired (stale-session guard: round-1 older than " + jsNum(sessionTtlMs) + "ms)");
                }

                byte[] message = Pca.decodeB64uStrict(req.get("message"), -1);
                if (message == null) return refuse("message not canonical base64url");
                if (!Pca.b64(groupPublicKey).equals(req.get("group_pk"))) return refuse("request names a different group key");

                Map<String, Object> expect = mapOf("policyAuthorityPublicKey", policyAuthorityPublicKey, "groupPublicKey", groupPublicKey, "message", message, "now", now.getAsDouble());
                Map<String, Object> allow = verifyAllowToken(req.get("allow"), expect);
                if (!Boolean.TRUE.equals(allow.get("ok"))) return refuse("policy authorization failed: " + allow.get("reason"));

                Object cs = req.get("commitments");
                List<FrostCommitment> commitments = decodeCommitments(cs == null ? new ArrayList<Object>() : cs);
                if (commitments.size() < threshold) return refuse("signing set below threshold t=" + threshold);
                FrostCommitment own = null;
                for (FrostCommitment c : commitments) if (c.identifier == identifier) { own = c; break; }
                if (own == null) return refuse("our commitment is not in the signing set");
                if (!Pca.b64(own.hiding).equals(Pca.b64(state.commitment.hiding)) || !Pca.b64(own.binding).equals(Pca.b64(state.commitment.binding))) {
                    return refuse("equivocation detected: our commitment in the signing set differs from our round-1 commitment");
                }
                List<VerificationShare> vss = decodeVerificationShares(req.get("verification_shares"));

                if (store != null) store.spend(sid);
                FrostSignOpts so = new FrostSignOpts();
                so.threshold = (int) Math.min(threshold, Integer.MAX_VALUE);
                so.verificationShare = verificationShare;
                so.verificationShares = vss;
                FrostSignatureShare sigShare = Frost.sign(identifier, share, groupPublicKey, state.nonces, message, commitments, so);

                sessions.remove(sid);
                spent.add(sid);
                return mapOf("ok", true, "identifier", identifier, "sig_share", Pca.b64(sigShare.sigShare));
            } catch (RuntimeException e) {
                return refuse(msg(e, "round-2 error"));
            }
        }
    }

    private static String jsNum(double d) { return d == Math.rint(d) && Math.abs(d) < 1e15 ? Long.toString((long) d) : Double.toString(d); }

    // ---- transport ---------------------------------------------------------------------------------------------------

    /** One signer as the coordinator sees it: requests and responses are the wire maps. */
    public interface SignerTransport {
        long identifier();
        Map<String, Object> round1(Map<String, Object> req) throws Exception;
        Map<String, Object> round2(Map<String, Object> req) throws Exception;
    }

    /** A separate {@link GuardianSignerService} object reached only through calls: state isolation in one address space. */
    public static SignerTransport inProcessTransport(GuardianSignerService service) {
        return new SignerTransport() {
            @Override public long identifier() { return service.identifier; }
            @Override public Map<String, Object> round1(Map<String, Object> req) { return service.round1(req); }
            @Override public Map<String, Object> round2(Map<String, Object> req) { return service.round2(req); }
        };
    }

    // ---- HTTP transport (JSON over loopback) ---------------------------------------------------------------------------------

    /** A running signer HTTP server. */
    public static final class SignerHttpServer implements AutoCloseable {
        public final String url;
        public final int port;
        private final com.sun.net.httpserver.HttpServer server;
        SignerHttpServer(com.sun.net.httpserver.HttpServer server, String host) {
            this.server = server;
            this.port = server.getAddress().getPort();
            this.url = "http://" + host + ":" + port;
        }
        @Override public void close() { server.stop(0); }
    }

    private static final int HTTP_BODY_LIMIT = 1 << 20;

    private static void send(com.sun.net.httpserver.HttpExchange ex, int code, Object body) throws java.io.IOException {
        byte[] out = Json.stringify(body).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("content-type", "application/json");
        ex.sendResponseHeaders(code, out.length);
        try (java.io.OutputStream os = ex.getResponseBody()) { os.write(out); }
    }

    /**
     * Serve one signer over HTTP: POST /round1 and POST /round2, JSON in and out (bytes base64url). Binds {@code host} (use
     * 127.0.0.1) on {@code port} (0: an ephemeral one). A handler error is a refusal response, never a leaked stack or share. For
     * process-level trust-domain separation run each service in its own OS process; the channel itself (confidentiality, availability)
     * is the deployment's responsibility.
     */
    public static SignerHttpServer startSignerHttpServer(GuardianSignerService service, String host, int port) throws java.io.IOException {
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress(host, port), 0);
        server.createContext("/", ex -> {
            try {
                if (!"POST".equals(ex.getRequestMethod())) { send(ex, 405, mapOf("ok", false, "reason", "method not allowed")); return; }
                String path = ex.getRequestURI().getPath();
                if (!path.equals("/round1") && !path.equals("/round2")) { send(ex, 404, mapOf("ok", false, "reason", "not found")); return; }
                byte[] raw = ex.getRequestBody().readNBytes(HTTP_BODY_LIMIT + 1);
                if (raw.length > HTTP_BODY_LIMIT) throw new IllegalArgumentException("request body too large");
                String text = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
                Object body = text.isEmpty() ? new LinkedHashMap<String, Object>() : Json.parseLenient(text);
                send(ex, 200, path.equals("/round1") ? service.round1(body) : service.round2(body));
            } catch (RuntimeException e) {
                send(ex, 400, mapOf("ok", false, "identifier", service.identifier, "refused", true, "reason", msg(e, "bad request")));
            } finally {
                ex.close();
            }
        });
        server.start();
        return new SignerHttpServer(server, host);
    }

    /** A transport that talks to a signer HTTP server (one per remote signer); {@code timeoutMs} bounds each call (default 10 s). */
    public static SignerTransport httpSignerTransport(String baseUrl, long identifier, Double timeoutMs) {
        long ms = timeoutMs == null ? 10_000 : (long) Math.ceil(timeoutMs);
        java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder().connectTimeout(java.time.Duration.ofMillis(ms)).build();
        return new SignerTransport() {
            private Map<String, Object> post(String path, Map<String, Object> body) throws Exception {
                java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder(java.net.URI.create(baseUrl + path)).timeout(java.time.Duration.ofMillis(ms))
                    .header("content-type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(Json.stringify(body))).build();
                String text = client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString()).body();
                Map<String, Object> out = obj(Json.parseLenient(text));
                if (out == null) throw new IllegalStateException("response is not an object");
                return out;
            }
            @Override public long identifier() { return identifier; }
            @Override public Map<String, Object> round1(Map<String, Object> req) throws Exception { return post("/round1", req); }
            @Override public Map<String, Object> round2(Map<String, Object> req) throws Exception { return post("/round2", req); }
        };
    }

    // ---- coordinator ---------------------------------------------------------------------------------------------------

    public static class CoordinatorError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        /** [{identifier, reason}]. */
        public final List<Map<String, Object>> refusals;
        public CoordinatorError(String message, List<Map<String, Object>> refusals) { super(message); this.refusals = refusals; }
    }

    /** The session exceeded its bounded round deadline; no signature was produced. */
    public static final class CoordinatorTimeoutError extends CoordinatorError {
        private static final long serialVersionUID = 1L;
        public final double timeoutMs;
        public CoordinatorTimeoutError(String message, double timeoutMs, List<Map<String, Object>> refusals) { super(message, refusals); this.timeoutMs = timeoutMs; }
    }

    private static final ExecutorService POOL = Executors.newCachedThreadPool(r -> { Thread t = new Thread(r, "frost-net"); t.setDaemon(true); return t; });

    /**
     * The network coordinator: it collects at least t commitments, forms the signing set, collects the matching shares and aggregates
     * (re-verifying). It holds no share and cannot forge the allow token, so it cannot sign on its own.
     */
    public static final class NetworkCoordinator {
        private final byte[] groupPublicKey;
        private final long threshold;
        private final List<SignerTransport> signers;
        private final List<Map<String, Object>> verificationShares;
        private final Map<Double, String> pkById = new HashMap<>();
        private final EquivocationGuard equivocation = new EquivocationGuard();
        private final Supplier<String> newSessionId;
        private final Double timeoutMs;

        /**
         * {@code opts}: groupPublicKey (32 bytes), threshold, signers (List of {@link SignerTransport}), verificationShares
         * ([{identifier, publicKey}]) or enroll (enrollment records), newSessionId (Supplier, default random), timeoutMs (optional).
         */
        @SuppressWarnings("unchecked")
        public NetworkCoordinator(Map<String, Object> opts) {
            if (!isBytes32(opts.get("groupPublicKey"))) throw new IllegalArgumentException("NetworkCoordinator: groupPublicKey must be 32 bytes");
            Object thr = opts.get("threshold");
            if (!IntentJs.isSafeInteger(thr) || IntentJs.num(thr) < 1) throw new IllegalArgumentException("NetworkCoordinator: threshold must be a positive integer");
            Object to = opts.get("timeoutMs");
            if (to != null && (!IntentJs.isFinite(to) || IntentJs.num(to) <= 0)) throw new IllegalArgumentException("NetworkCoordinator: timeoutMs must be a positive finite number");
            this.groupPublicKey = (byte[]) opts.get("groupPublicKey");
            this.threshold = IntentJs.lng(thr);
            this.signers = new ArrayList<>((List<SignerTransport>) opts.get("signers"));
            if (opts.get("enroll") != null) {
                this.verificationShares = enrollVerificationShares(opts.get("enroll"), mapOf("groupPublicKey", opts.get("groupPublicKey")));
            } else if (opts.get("verificationShares") != null) {
                this.verificationShares = new ArrayList<>();
                for (Object v : (List<?>) opts.get("verificationShares")) this.verificationShares.add(obj(v));
            } else {
                throw new IllegalArgumentException("NetworkCoordinator: provide verificationShares or enroll");
            }
            for (Map<String, Object> v : verificationShares) pkById.put(IntentJs.num(v.get("identifier")), Pca.b64((byte[]) v.get("publicKey")));
            this.newSessionId = opts.get("newSessionId") instanceof Supplier ? (Supplier<String>) opts.get("newSessionId") : () -> Pca.b64(Frost.randomScalarBytes());
            this.timeoutMs = to == null ? null : IntentJs.num(to);
        }

        /**
         * Drive one t-of-n session. {@code opts}: signerIds (List of numbers; default the first t signers), timeoutMs (a call-level
         * window that overrides the constructor's; a non-positive or non-finite value means no deadline). Returns
         * {signature (bytes), sessionId, signers}; throws {@link CoordinatorError} or {@link CoordinatorTimeoutError}.
         */
        public Map<String, Object> sign(Object message, Object allow, Map<String, Object> opts) {
            Object call = opts == null ? null : opts.get("timeoutMs");
            Double windowMs = call != null ? IntentJs.num(call) : timeoutMs;
            if (windowMs == null || windowMs.isNaN() || windowMs.isInfinite() || windowMs <= 0) return drive(message, allow, opts);
            CompletableFuture<Map<String, Object>> run = CompletableFuture.supplyAsync(() -> drive(message, allow, opts), POOL);
            try {
                return run.get((long) Math.ceil(windowMs), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                run.cancel(true);
                throw new CoordinatorTimeoutError("coordinator: signing session did not reach threshold within " + jsNum(windowMs) + "ms", windowMs, new ArrayList<>());
            } catch (ExecutionException e) {
                Throwable c = e.getCause();
                if (c instanceof RuntimeException) throw (RuntimeException) c;
                throw new IllegalStateException(c);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }

        private static Map<String, Object> refusal(Object identifier, Object reason) { return mapOf("identifier", identifier, "reason", reason); }

        private Map<String, Object> call(SignerTransport s, boolean first, Map<String, Object> req) {
            try {
                return first ? s.round1(req) : s.round2(req);
            } catch (Exception e) {
                Map<String, Object> m = mapOf("ok", false, "identifier", s.identifier());
                if (!first) m.put("refused", true);
                m.put("reason", msg(e, "unreachable"));
                return m;
            }
        }

        private Map<String, Object> drive(Object messageO, Object allow, Map<String, Object> opts) {
            if (!(messageO instanceof byte[])) throw new IllegalArgumentException("coordinator.sign: message must be bytes");
            byte[] message = (byte[]) messageO;
            List<SignerTransport> chosen = new ArrayList<>();
            Object ids = opts == null ? null : opts.get("signerIds");
            if (ids != null) {
                Set<Double> want = new HashSet<>();
                if (ids instanceof List) for (Object i : (List<?>) ids) { Double d = IntentJs.num(i); if (d != null) want.add(d == 0.0 ? 0.0 : d); }
                for (SignerTransport s : signers) if (want.contains((double) s.identifier())) chosen.add(s);
            } else {
                for (int i = 0; i < signers.size() && i < threshold; i++) chosen.add(signers.get(i));
            }
            if (chosen.size() < threshold) throw new CoordinatorError("coordinator: only " + chosen.size() + " signer(s) selected, need t=" + threshold, new ArrayList<>());
            String sessionId = newSessionId.get();

            // Round 1: collect commitments.
            Map<String, Object> r1req = mapOf("typ", "pca.frost.round1.v1", "session_id", sessionId);
            List<CompletableFuture<Map<String, Object>>> f1 = new ArrayList<>();
            for (SignerTransport s : chosen) f1.add(CompletableFuture.supplyAsync(() -> call(s, true, new LinkedHashMap<>(r1req)), POOL));
            List<Map<String, Object>> refusals = new ArrayList<>();
            List<SignerTransport> committedT = new ArrayList<>();
            List<Map<String, Object>> committedC = new ArrayList<>();
            for (int i = 0; i < chosen.size(); i++) {
                Map<String, Object> resp = join(f1.get(i));
                SignerTransport s = chosen.get(i);
                if (!truthy(resp.get("ok"))) { refusals.add(refusal(resp.get("identifier"), resp.get("reason"))); continue; }
                Object rid = resp.get("identifier");
                String expectedPk = IntentJs.num(rid) == null ? null : pkById.get(IntentJs.num(rid));
                if (expectedPk == null) { refusals.add(refusal(rid, "no verification share on record for this signer")); continue; }
                Map<String, Object> popM = obj(resp.get("pop"));
                if (popM == null || !numEq(popM.get("identifier"), rid) || !expectedPk.equals(popM.get("publicKey")) || !verifySignerPoP(popM, mapOf("groupPublicKey", groupPublicKey))) {
                    refusals.add(refusal(rid, "invalid or missing proof-of-possession (rogue-key defense)"));
                    continue;
                }
                try {
                    equivocation.observe(sessionId, 1L, rid, resp.containsKey("commitment") ? resp.get("commitment") : UNDEFINED);
                } catch (RuntimeException e) {
                    refusals.add(refusal(rid, e instanceof EquivocationError ? e.getMessage() : "equivocation check failed"));
                    continue;
                }
                committedT.add(s);
                committedC.add(obj(resp.get("commitment")));
            }
            if (committedT.size() < threshold) {
                throw new CoordinatorError("coordinator: round 1 produced " + committedT.size() + " commitment(s), need t=" + threshold, refusals);
            }
            int t = (int) threshold;
            List<SignerTransport> setT = new ArrayList<>(committedT.subList(0, t));
            List<Object> commitments = new ArrayList<>(committedC.subList(0, t));
            Set<Double> setIds = new HashSet<>();
            for (Object c : commitments) setIds.add(c instanceof Map ? IntentJs.num(((Map<?, ?>) c).get("identifier")) : null);
            List<Map<String, Object>> vsWire = new ArrayList<>();
            List<Map<String, Object>> vsSet = new ArrayList<>();
            for (Map<String, Object> v : verificationShares) {
                if (!setIds.contains(IntentJs.num(v.get("identifier")))) continue;
                vsSet.add(v);
                vsWire.add(mapOf("identifier", v.get("identifier"), "publicKey", Pca.b64((byte[]) v.get("publicKey"))));
            }
            if (vsWire.size() != setT.size()) throw new CoordinatorError("coordinator: missing a verification share for a signer in the set", new ArrayList<>());

            // Round 2: collect signature shares.
            List<CompletableFuture<Map<String, Object>>> f2 = new ArrayList<>();
            for (SignerTransport s : setT) {
                Map<String, Object> req = mapOf("typ", "pca.frost.round2.v1", "session_id", sessionId, "message", Pca.b64(message), "group_pk", Pca.b64(groupPublicKey),
                    "commitments", commitments, "verification_shares", vsWire, "allow", allow);
                f2.add(CompletableFuture.supplyAsync(() -> call(s, false, req), POOL));
            }
            List<FrostSignatureShare> sigShares = new ArrayList<>();
            for (CompletableFuture<Map<String, Object>> f : f2) {
                Map<String, Object> resp = join(f);
                if (!truthy(resp.get("ok"))) { refusals.add(refusal(resp.get("identifier"), resp.get("reason"))); continue; }
                Object rid = resp.get("identifier");
                try {
                    equivocation.observe(sessionId, 2L, rid, mapOf("sig_share", resp.containsKey("sig_share") ? resp.get("sig_share") : UNDEFINED));
                } catch (RuntimeException e) {
                    refusals.add(refusal(rid, e instanceof EquivocationError ? e.getMessage() : "equivocation check failed"));
                    continue;
                }
                byte[] sb = Pca.decodeB64uStrict(resp.get("sig_share"), 32);
                if (sb == null) refusals.add(refusal(rid, "malformed signature share"));
                else sigShares.add(new FrostSignatureShare(IntentJs.lng(rid), sb));
            }
            if (sigShares.size() < threshold) throw new CoordinatorError("coordinator: round 2 produced " + sigShares.size() + " share(s), need t=" + threshold, refusals);

            List<FrostCommitment> agg = new ArrayList<>();
            for (Object c : commitments) agg.add(decodeCommitment(c));
            List<VerificationShare> vss = new ArrayList<>();
            for (Map<String, Object> v : vsSet) vss.add(new VerificationShare(IntentJs.lng(v.get("identifier")), (byte[]) v.get("publicKey")));
            byte[] signature = Frost.aggregate(message, agg, sigShares, groupPublicKey, t, vss);
            List<Object> signedBy = new ArrayList<>();
            for (Object c : commitments) signedBy.add(((Map<?, ?>) c).get("identifier"));
            return mapOf("signature", signature, "sessionId", sessionId, "signers", signedBy);
        }

        private static Map<String, Object> join(CompletableFuture<Map<String, Object>> f) {
            try {
                return f.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            } catch (ExecutionException e) {
                Throwable c = e.getCause();
                if (c instanceof RuntimeException) throw (RuntimeException) c;
                throw new IllegalStateException(c);
            }
        }
    }
}
