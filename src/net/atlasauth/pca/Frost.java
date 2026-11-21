package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import net.atlasauth.pca.ratchet.EdwardsPoint;

/**
 * FROST (Flexible Round-Optimized Schnorr Threshold) signatures for Ed25519, RFC 9591, ciphersuite FROST(Ed25519, SHA-512)
 * ("FROST-ED25519-SHA512-v1"). A trusted-dealer split, the two signing rounds, per-share verification and aggregation; the aggregate is an
 * ordinary 64-byte Ed25519 signature under the group public key. Group arithmetic is the shared Edwards25519 implementation
 * ({@link EdwardsPoint}); scalars are BigInteger mod L.
 *
 * <p>Safety checks mirror the reference: strict canonical, prime-order, non-small-order points everywhere; one-shot nonces (a nonce array is
 * zeroised after use and its commitment is remembered, so reuse, which would leak the signing share, is refused); every signature share is
 * verified before aggregation; the aggregate is verified as strict Ed25519 before it is returned.
 * shortcut: BigInteger scalar arithmetic is not constant time in the operand values; move to a constant-time scalar library if signing
 * shares must run next to untrusted code.
 */
public final class Frost {
    private Frost() {}

    public static final BigInteger L = EdwardsPoint.ORDER;
    public static final String CONTEXT_STRING = "FROST-ED25519-SHA512-v1";
    private static final byte[] CTX = CONTEXT_STRING.getBytes(StandardCharsets.UTF_8);
    private static final long MAX_ID = 9007199254740991L; // Number.MAX_SAFE_INTEGER
    public static final int SPENT_COMMITMENT_CAP = 262_144;
    private static final SecureRandom RNG = new SecureRandom();

    // ---- records --------------------------------------------------------------------------------------------------

    public static final class FrostParticipantShare {
        public final long identifier;
        public final byte[] share, publicKey;
        public FrostParticipantShare(long identifier, byte[] share, byte[] publicKey) { this.identifier = identifier; this.share = share; this.publicKey = publicKey; }
    }

    public static final class FrostKeygenOpts {
        public byte[] secret;
        public List<byte[]> coefficients;
        public long[] identifiers;
    }

    public static final class FrostKeygenResult {
        public final byte[] groupPublicKey;
        public final List<FrostParticipantShare> participantShares;
        public final List<byte[]> groupCommitment;
        FrostKeygenResult(byte[] g, List<FrostParticipantShare> s, List<byte[]> c) { groupPublicKey = g; participantShares = s; groupCommitment = c; }
    }

    /** One participant's one-shot secret nonces; the arrays are zeroised by {@link #sign}. */
    public static final class FrostNonces {
        public byte[] hiding, binding;
        public FrostNonces(byte[] hiding, byte[] binding) { this.hiding = hiding; this.binding = binding; }
    }

    public static final class FrostCommitment {
        public final long identifier;
        public final byte[] hiding, binding;
        public FrostCommitment(long identifier, byte[] hiding, byte[] binding) { this.identifier = identifier; this.hiding = hiding; this.binding = binding; }
    }

    public static final class FrostCommitResult {
        public final byte[] hidingNonce, bindingNonce;
        public final FrostCommitment commitment;
        FrostCommitResult(byte[] h, byte[] b, FrostCommitment c) { hidingNonce = h; bindingNonce = b; commitment = c; }
        public FrostNonces nonces() { return new FrostNonces(hidingNonce, bindingNonce); }
    }

    public static final class FrostSignatureShare {
        public final long identifier;
        public final byte[] sigShare;
        public FrostSignatureShare(long identifier, byte[] sigShare) { this.identifier = identifier; this.sigShare = sigShare; }
    }

    /** A participant's public verification share (share * B). */
    public static final class VerificationShare {
        public final long identifier;
        public final byte[] publicKey;
        public VerificationShare(long identifier, byte[] publicKey) { this.identifier = identifier; this.publicKey = publicKey; }
    }

    public static final class FrostSignOpts {
        public Integer threshold;
        public byte[] verificationShare;
        public List<VerificationShare> verificationShares;
    }

    // ---- scalars and hashes ---------------------------------------------------------------------------------------

    static BigInteger mod(BigInteger a) { return a.mod(L); }

    private static byte[] le32(BigInteger n) {
        byte[] out = new byte[32];
        byte[] be = n.toByteArray();
        for (int i = 0; i < 32 && i < be.length; i++) out[i] = be[be.length - 1 - i];
        return out;
    }

    private static BigInteger fromLe(byte[] b) {
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) be[b.length - 1 - i] = b[i];
        return new BigInteger(1, be);
    }

    public static byte[] scalarToBytes(BigInteger s) { return le32(mod(s)); }

    /** Little-endian 0..64 bytes reduced mod L (the wide reduction HashToScalar needs); more than 64 bytes throws, like the reference. */
    public static BigInteger bytesToScalar(byte[] b) {
        if (b.length == 0) return BigInteger.ZERO;
        if (b.length > 64) throw new IllegalArgumentException("ct-scalar: reduce takes 1..64 bytes");
        return mod(fromLe(b));
    }

    public static boolean isCanonicalScalar(byte[] b) { return b != null && b.length == 32 && fromLe(b).compareTo(L) < 0; }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int i = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, i, p.length); i += p.length; }
        return out;
    }

    static byte[] sha512(byte[] m) {
        try { return MessageDigest.getInstance("SHA-512").digest(m); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static byte[] utf8(String s) { return Json.utf8(s); }

    private static BigInteger hashToScalar(byte[] m) { return bytesToScalar(sha512(m)); }

    public static BigInteger H1(byte[] m) { return hashToScalar(concat(CTX, utf8("rho"), m)); }
    public static BigInteger H2(byte[] m) { return hashToScalar(m); }
    public static BigInteger H3(byte[] m) { return hashToScalar(concat(CTX, utf8("nonce"), m)); }
    public static byte[] H4(byte[] m) { return sha512(concat(CTX, utf8("msg"), m)); }
    public static byte[] H5(byte[] m) { return sha512(concat(CTX, utf8("com"), m)); }

    // ---- points ---------------------------------------------------------------------------------------------------

    static EdwardsPoint mulBase(BigInteger s) {
        BigInteger v = mod(s);
        return v.signum() == 0 ? EdwardsPoint.ZERO : EdwardsPoint.BASE.multiply(v);
    }

    static EdwardsPoint mulPoint(EdwardsPoint pt, BigInteger s) {
        BigInteger v = mod(s);
        return v.signum() == 0 ? EdwardsPoint.ZERO : pt.multiply(v);
    }

    /** Strict decode: canonical encoding, on the curve, not small order, in the prime-order subgroup. Throws otherwise. */
    public static EdwardsPoint decodeSafePoint(byte[] b) {
        if (b == null || b.length != 32) throw new IllegalArgumentException("frost: point must be 32 bytes");
        EdwardsPoint pt;
        try { pt = EdwardsPoint.fromBytes(b); } catch (IllegalArgumentException e) { throw new IllegalArgumentException("frost: invalid point encoding"); }
        if (pt.isSmallOrder()) throw new IllegalArgumentException("frost: small-order point rejected");
        if (!pt.isTorsionFree()) throw new IllegalArgumentException("frost: point is not in the prime-order subgroup");
        if (!Arrays.equals(pt.toBytes(), b)) throw new IllegalArgumentException("frost: non-canonical point encoding");
        return pt;
    }

    private static void assertValidId(long id) {
        if (id <= 0 || id > MAX_ID) throw new IllegalArgumentException("frost: participant identifier must be a positive safe integer");
    }

    private static void validateCommitments(List<FrostCommitment> list, Integer threshold) {
        if (list == null || list.isEmpty()) throw new IllegalArgumentException("frost: empty commitment list");
        if (threshold != null) {
            if (threshold < 1) throw new IllegalArgumentException("frost: invalid threshold");
            if (list.size() < threshold) throw new IllegalArgumentException("frost: need at least t=" + threshold + " commitments (got " + list.size() + ")");
        }
        Set<Long> seen = new HashSet<>();
        for (FrostCommitment c : list) {
            if (c == null) throw new IllegalArgumentException("frost: malformed commitment");
            assertValidId(c.identifier);
            if (!seen.add(c.identifier)) throw new IllegalArgumentException("frost: duplicate commitment identifier " + c.identifier);
            decodeSafePoint(c.hiding);
            decodeSafePoint(c.binding);
        }
    }

    // ---- key generation -------------------------------------------------------------------------------------------

    static byte[] randomScalarBytes() { byte[] b = new byte[32]; RNG.nextBytes(b); return b; }

    /** Trusted-dealer Shamir split of a (given or fresh) group secret into n shares with threshold t (RFC 9591 appendix C). */
    public static FrostKeygenResult trustedDealerKeygen(int t, int n, FrostKeygenOpts opts) {
        if (opts == null) opts = new FrostKeygenOpts();
        if (t < 1 || n < t) throw new IllegalArgumentException("frostTrustedDealerKeygen: need 1 <= t <= n (got t=" + t + ", n=" + n + ")");
        long[] ids = opts.identifiers;
        if (ids == null) { ids = new long[n]; for (int i = 0; i < n; i++) ids[i] = i + 1; }
        if (ids.length != n) throw new IllegalArgumentException("frostTrustedDealerKeygen: identifiers.length must equal n");
        Set<Long> distinct = new HashSet<>();
        for (long x : ids) distinct.add(x);
        if (distinct.size() != n) throw new IllegalArgumentException("frostTrustedDealerKeygen: identifiers must be distinct");
        for (long x : ids) if (x <= 0 || x > MAX_ID) throw new IllegalArgumentException("frostTrustedDealerKeygen: identifiers must be positive integers");

        BigInteger secret = bytesToScalar(opts.secret != null ? opts.secret : randomScalarBytes());
        List<BigInteger> coeffs = new ArrayList<>();
        coeffs.add(secret);
        for (int i = 1; i < t; i++) {
            byte[] c = opts.coefficients != null && i - 1 < opts.coefficients.size() ? opts.coefficients.get(i - 1) : null;
            coeffs.add(bytesToScalar(c != null ? c : randomScalarBytes()));
        }
        List<FrostParticipantShare> shares = new ArrayList<>();
        for (long id : ids) {
            BigInteger x = BigInteger.valueOf(id), acc = BigInteger.ZERO;
            for (int j = coeffs.size() - 1; j >= 0; j--) acc = mod(acc.multiply(x).add(coeffs.get(j)));
            shares.add(new FrostParticipantShare(id, scalarToBytes(acc), mulBase(acc).toBytes()));
        }
        List<byte[]> commitment = new ArrayList<>();
        for (BigInteger a : coeffs) commitment.add(mulBase(a).toBytes());
        return new FrostKeygenResult(commitment.get(0), shares, commitment);
    }

    /** share * B, the participant's public verification share. */
    public static byte[] verifyingShare(byte[] share) { return mulBase(bytesToScalar(share)).toBytes(); }

    // ---- round 1 --------------------------------------------------------------------------------------------------

    private static BigInteger nonceGenerate(byte[] randomness, byte[] secretShare) {
        if (randomness.length != 32) throw new IllegalArgumentException("frostCommit: nonce randomness must be 32 bytes");
        return H3(concat(randomness, scalarToBytes(bytesToScalar(secretShare))));
    }

    /** Round 1: the one-shot nonce pair and its public commitment. Randomness is drawn fresh unless given (tests / vectors). */
    public static FrostCommitResult commit(FrostParticipantShare p, byte[] hidingRandomness, byte[] bindingRandomness) {
        byte[] hr = hidingRandomness != null ? hidingRandomness : randomScalarBytes();
        byte[] br = bindingRandomness != null ? bindingRandomness : randomScalarBytes();
        BigInteger h = nonceGenerate(hr, p.share), b = nonceGenerate(br, p.share);
        return new FrostCommitResult(scalarToBytes(h), scalarToBytes(b), new FrostCommitment(p.identifier, mulBase(h).toBytes(), mulBase(b).toBytes()));
    }

    public static FrostCommitResult commit(FrostParticipantShare p) { return commit(p, null, null); }

    // ---- round 2 helpers ------------------------------------------------------------------------------------------

    private static List<FrostCommitment> sortCommitments(List<FrostCommitment> list) {
        List<FrostCommitment> out = new ArrayList<>(list);
        out.sort((a, b) -> Long.compare(a.identifier, b.identifier));
        return out;
    }

    private static byte[] encodeCommitmentList(List<FrostCommitment> list) {
        byte[][] parts = new byte[list.size() * 3][];
        int i = 0;
        for (FrostCommitment c : list) {
            parts[i++] = scalarToBytes(BigInteger.valueOf(c.identifier));
            parts[i++] = c.hiding;
            parts[i++] = c.binding;
        }
        return concat(parts);
    }

    private static Map<Long, BigInteger> computeBindingFactors(byte[] groupPublicKey, List<FrostCommitment> list, byte[] msg) {
        byte[] prefix = concat(groupPublicKey, H4(msg), H5(encodeCommitmentList(list)));
        Map<Long, BigInteger> out = new HashMap<>();
        for (FrostCommitment c : list) out.put(c.identifier, H1(concat(prefix, scalarToBytes(BigInteger.valueOf(c.identifier)))));
        return out;
    }

    private static EdwardsPoint computeGroupCommitment(List<FrostCommitment> list, Map<Long, BigInteger> bindingFactors) {
        EdwardsPoint r = EdwardsPoint.ZERO;
        for (FrostCommitment c : list) {
            r = r.add(decodeSafePoint(c.hiding)).add(mulPoint(decodeSafePoint(c.binding), bindingFactors.get(c.identifier)));
        }
        return r;
    }

    private static BigInteger computeChallenge(byte[] r, byte[] groupPublicKey, byte[] msg) { return H2(concat(r, groupPublicKey, msg)); }

    private static BigInteger deriveInterpolatingValue(List<Long> participants, long i) {
        if (!participants.contains(i)) throw new IllegalArgumentException("frost: identifier not in participant list");
        BigInteger num = BigInteger.ONE, den = BigInteger.ONE, xi = BigInteger.valueOf(i);
        for (long j : participants) {
            if (j == i) continue;
            BigInteger xj = BigInteger.valueOf(j);
            num = mod(num.multiply(xj));
            den = mod(den.multiply(xj.subtract(xi)));
        }
        if (den.signum() == 0) throw new IllegalArgumentException("frost: modular inverse of zero");
        BigInteger lam = mod(num.multiply(den.modInverse(L)));
        if (lam.signum() == 0) throw new IllegalArgumentException("frost: zero Lagrange coefficient");
        return lam;
    }

    // ---- one-shot nonce registry ----------------------------------------------------------------------------------

    private static final Set<byte[]> SPENT_NONCES = Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap<>()));
    private static final Set<String> SPENT_COMMITMENTS = new LinkedHashSet<>();

    private static String commitmentKey(char kind, byte[] point) { return kind + Keys.b64u(point); }

    private static void claimCommitment(String key) {
        synchronized (SPENT_COMMITMENTS) {
            SPENT_COMMITMENTS.add(key);
            if (SPENT_COMMITMENTS.size() > SPENT_COMMITMENT_CAP) {
                Iterator<String> it = SPENT_COMMITMENTS.iterator();
                it.next();
                it.remove();
            }
        }
    }

    private static boolean commitmentSpent(String key) { synchronized (SPENT_COMMITMENTS) { return SPENT_COMMITMENTS.contains(key); } }

    private static boolean isZero(byte[] b) {
        int acc = 0;
        for (byte x : b) acc |= x;
        return acc == 0;
    }

    // ---- round 2 --------------------------------------------------------------------------------------------------

    /**
     * Round 2: this participant's signature share. Consumes the nonces (zeroised, and remembered so the same nonce can never be signed with twice).
     * With {@code verificationShare(s)} in the options the share and the group key are cross-checked before any secret is used.
     */
    public static FrostSignatureShare sign(long identifier, byte[] share, byte[] groupPublicKey, FrostNonces nonces, byte[] message,
                                           List<FrostCommitment> signingCommitments, FrostSignOpts opts) {
        if (opts == null) opts = new FrostSignOpts();
        assertValidId(identifier);
        validateCommitments(signingCommitments, opts.threshold);
        decodeSafePoint(groupPublicKey);
        if (nonces == null || nonces.hiding == null || nonces.binding == null) throw new IllegalArgumentException("frostSign: malformed nonces");
        if (SPENT_NONCES.contains(nonces.hiding) || SPENT_NONCES.contains(nonces.binding)) {
            throw new IllegalArgumentException("frostSign: nonces already used (one-shot; reuse would leak the signing share)");
        }
        if (isZero(nonces.hiding) || isZero(nonces.binding)) throw new IllegalArgumentException("frostSign: zero/zeroized nonce");
        if (nonces.hiding == nonces.binding) throw new IllegalArgumentException("frostSign: hiding and binding nonce must differ");

        List<FrostCommitment> list = sortCommitments(signingCommitments);
        FrostCommitment mine = null;
        for (FrostCommitment c : list) if (c.identifier == identifier) { mine = c; break; }
        if (mine == null) throw new IllegalArgumentException("frostSign: this identifier has no commitment in the set");

        BigInteger hiding = bytesToScalar(nonces.hiding), binding = bytesToScalar(nonces.binding), sk = bytesToScalar(share);
        if (!mulBase(hiding).sameAs(decodeSafePoint(mine.hiding)) || !mulBase(binding).sameAs(decodeSafePoint(mine.binding))) {
            throw new IllegalArgumentException("frostSign: own commitment does not match nonces");
        }
        String hKey = commitmentKey('h', mine.hiding), bKey = commitmentKey('b', mine.binding);
        if (commitmentSpent(hKey) || commitmentSpent(bKey)) {
            throw new IllegalArgumentException("frostSign: nonces already used (one-shot; reuse would leak the signing share)");
        }
        if (opts.verificationShare != null && !mulBase(sk).sameAs(decodeSafePoint(opts.verificationShare))) {
            throw new IllegalArgumentException("frostSign: share does not match verification share");
        }
        List<Long> participants = new ArrayList<>();
        for (FrostCommitment c : list) participants.add(c.identifier);
        if (opts.verificationShares != null) {
            EdwardsPoint acc = EdwardsPoint.ZERO;
            for (long id : participants) {
                VerificationShare vs = null;
                for (VerificationShare v : opts.verificationShares) if (v.identifier == id) { vs = v; break; }
                if (vs == null) throw new IllegalArgumentException("frostSign: missing verification share for " + id);
                acc = acc.add(mulPoint(decodeSafePoint(vs.publicKey), deriveInterpolatingValue(participants, id)));
            }
            if (!acc.sameAs(decodeSafePoint(groupPublicKey))) throw new IllegalArgumentException("frostSign: group public key does not match the verification shares");
        }

        Map<Long, BigInteger> bindingFactors = computeBindingFactors(groupPublicKey, list, message);
        BigInteger bf = bindingFactors.get(identifier);
        EdwardsPoint r = computeGroupCommitment(list, bindingFactors);
        BigInteger lambda = deriveInterpolatingValue(participants, identifier);
        BigInteger c = computeChallenge(r.toBytes(), groupPublicKey, message);
        BigInteger z = mod(hiding.add(binding.multiply(bf)).add(lambda.multiply(sk).multiply(c)));

        SPENT_NONCES.add(nonces.hiding);
        SPENT_NONCES.add(nonces.binding);
        claimCommitment(hKey);
        claimCommitment(bKey);
        Arrays.fill(nonces.hiding, (byte) 0);
        Arrays.fill(nonces.binding, (byte) 0);
        return new FrostSignatureShare(identifier, scalarToBytes(z));
    }

    /** RFC 9591 section 5.3: one signature share checked against its verification share. Never throws; any malformed input is false. */
    public static boolean verifySigShare(long identifier, byte[] publicKey, FrostCommitment commitment, FrostSignatureShare sigShare,
                                         List<FrostCommitment> signingCommitments, byte[] groupPublicKey, byte[] message) {
        try {
            validateCommitments(signingCommitments, null);
            List<FrostCommitment> list = sortCommitments(signingCommitments);
            Map<Long, BigInteger> bindingFactors = computeBindingFactors(groupPublicKey, list, message);
            BigInteger bf = bindingFactors.get(identifier);
            if (bf == null) return false;
            EdwardsPoint r = computeGroupCommitment(list, bindingFactors);
            EdwardsPoint commShare = decodeSafePoint(commitment.hiding).add(mulPoint(decodeSafePoint(commitment.binding), bf));
            BigInteger c = computeChallenge(r.toBytes(), groupPublicKey, message);
            List<Long> participants = new ArrayList<>();
            for (FrostCommitment x : list) participants.add(x.identifier);
            BigInteger lambda = deriveInterpolatingValue(participants, identifier);
            if (!isCanonicalScalar(sigShare.sigShare)) return false; // z and z + L must not both verify
            EdwardsPoint lhs = mulBase(bytesToScalar(sigShare.sigShare));
            EdwardsPoint rhs = commShare.add(mulPoint(decodeSafePoint(publicKey), mod(c.multiply(lambda))));
            return lhs.sameAs(rhs);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Combine the signature shares into the 64-byte Ed25519 signature. Every share is verified against its verification share first, a missing
     * or extra share is refused, and the result must verify as strict Ed25519 under the group key.
     */
    public static byte[] aggregate(byte[] message, List<FrostCommitment> signingCommitments, List<FrostSignatureShare> sigShares, byte[] groupPublicKey,
                                   Integer threshold, List<VerificationShare> verificationShares) {
        validateCommitments(signingCommitments, threshold);
        decodeSafePoint(groupPublicKey);
        List<FrostCommitment> list = sortCommitments(signingCommitments);
        if (sigShares == null || sigShares.size() != list.size()) throw new IllegalArgumentException("frostAggregate: need exactly one signature share per commitment");
        Set<Long> shareIds = new HashSet<>();
        for (FrostSignatureShare s : sigShares) {
            boolean known = false;
            for (FrostCommitment c : list) if (c.identifier == s.identifier) { known = true; break; }
            if (!known) throw new IllegalArgumentException("frostAggregate: share from non-signer");
            if (!shareIds.add(s.identifier)) throw new IllegalArgumentException("frostAggregate: duplicate signature share");
        }
        if (verificationShares == null) throw new IllegalArgumentException("frostAggregate: verificationShares are required (every signature share is verified before aggregation)");
        for (FrostSignatureShare s : sigShares) {
            VerificationShare vs = null;
            for (VerificationShare v : verificationShares) if (v.identifier == s.identifier) { vs = v; break; }
            FrostCommitment commitment = null;
            for (FrostCommitment c : list) if (c.identifier == s.identifier) { commitment = c; break; }
            if (vs == null || !verifySigShare(s.identifier, vs.publicKey, commitment, s, list, groupPublicKey, message)) {
                throw new IllegalArgumentException("frostAggregate: invalid signature share from participant " + s.identifier);
            }
        }
        EdwardsPoint r = computeGroupCommitment(list, computeBindingFactors(groupPublicKey, list, message));
        BigInteger z = BigInteger.ZERO;
        for (FrostSignatureShare s : sigShares) z = mod(z.add(bytesToScalar(s.sigShare)));
        byte[] sig = concat(r.toBytes(), scalarToBytes(z));
        if (!EdStrict.verify(groupPublicKey, message, sig)) throw new IllegalArgumentException("frostAggregate: aggregate signature does not verify (a share is invalid)");
        return sig;
    }

    /**
     * Run both rounds in-process for a quorum of participant shares (each carries its verification share) and return the aggregate signature.
     * Fails closed: an empty or sub-threshold quorum, a duplicate participant, or any invalid share throws.
     */
    public static byte[] cosign(byte[] groupPublicKey, List<FrostParticipantShare> quorum, byte[] message, Integer threshold) {
        if (quorum == null || quorum.isEmpty()) throw new IllegalArgumentException("frostCosign: empty signing quorum");
        if (threshold != null && quorum.size() < threshold) throw new IllegalArgumentException("frostCosign: quorum of " + quorum.size() + " is below the threshold t=" + threshold);
        Set<Long> ids = new HashSet<>();
        for (FrostParticipantShare p : quorum) {
            assertValidId(p.identifier);
            if (!ids.add(p.identifier)) throw new IllegalArgumentException("frostCosign: duplicate participant " + p.identifier + " in quorum");
        }
        List<VerificationShare> vss = new ArrayList<>();
        List<FrostCommitResult> commits = new ArrayList<>();
        List<FrostCommitment> commitments = new ArrayList<>();
        for (FrostParticipantShare p : quorum) vss.add(new VerificationShare(p.identifier, p.publicKey));
        for (FrostParticipantShare p : quorum) { FrostCommitResult c = commit(p); commits.add(c); commitments.add(c.commitment); }
        List<FrostSignatureShare> sigShares = new ArrayList<>();
        for (int i = 0; i < quorum.size(); i++) {
            FrostParticipantShare p = quorum.get(i);
            FrostSignOpts o = new FrostSignOpts();
            o.threshold = threshold; o.verificationShare = p.publicKey; o.verificationShares = vss;
            sigShares.add(sign(p.identifier, p.share, groupPublicKey, commits.get(i).nonces(), message, commitments, o));
        }
        return aggregate(message, commitments, sigShares, groupPublicKey, threshold, vss);
    }
}
