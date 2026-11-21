package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import net.atlasauth.pca.ratchet.EdwardsPoint;

/**
 * FROST distributed key generation (Pedersen with Feldman commitments): round 1 (coefficient commitments and a proof of knowledge of a_0),
 * round 2 (shares signed under C_0, so a bad share is non-repudiable), complaints, rebuttals, blame resolution, the qualified set,
 * transcript echo agreement and finalize. Packages, complaints, rebuttals and echoes are JSON-shaped maps (identifiers as numbers, bytes
 * as base64url strings), exactly as they travel on the wire; every verifier treats malformed input as a refusal, never as acceptance.
 * Randomness (coefficients, proof nonces, the session id) comes from a {@code Supplier<byte[]>} of 32-byte draws, the system CSPRNG by default.
 */
public final class FrostDkg {
    private FrostDkg() {}

    private static final byte[] CTX = Json.utf8(Frost.CONTEXT_STRING);
    private static final byte[] DKG_POP_DST = Json.utf8("dkg-pop");
    private static final byte[] DKG_SHARE_DST = Json.utf8("dkg-share");
    private static final byte[] DKG_SHARE_NONCE_DST = Json.utf8("dkg-share-nonce");
    private static final Supplier<byte[]> SECURE = Frost::randomScalarBytes;

    // ---- helpers --------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) { return o instanceof List ? (List<Object>) o : null; }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static BigInteger mod(BigInteger a) { return Frost.mod(a); }

    private static byte[] sb(BigInteger s) { return Frost.scalarToBytes(s); }

    private static BigInteger hashToScalar(byte[] m) { return Frost.bytesToScalar(Frost.sha512(m)); }

    private static EdwardsPoint decodePoint(byte[] b) { return Frost.decodeSafePoint(b); }

    private static boolean isInt(Object o) {
        Double d = IntentJs.num(o);
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d);
    }

    private static boolean posInteger(Object o) { return isInt(o) && IntentJs.num(o) > 0; }

    /** JavaScript {@code BigInt(x)} of an identifier: an integer-valued number; anything else throws. */
    private static BigInteger bigId(Object o) {
        if (!isInt(o)) throw new IllegalArgumentException("cannot convert to a BigInt");
        return new BigDecimal(IntentJs.num(o)).toBigIntegerExact();
    }

    private static boolean numEq(Object a, Object b) {
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    private static Double key(Object o) {
        Double d = IntentJs.num(o);
        return d == null ? null : (d == 0.0 ? Double.valueOf(0.0) : d);
    }

    private static byte[] ub(Object s) {
        byte[] b = Pca.decodeB64uStrict(s, -1);
        if (b == null) throw new IllegalArgumentException("not canonical base64url");
        return b;
    }

    private static byte[] bytesArg(Object o) {
        if (!(o instanceof byte[])) throw new IllegalArgumentException("Uint8Array expected");
        return (byte[]) o;
    }

    private static String b64u(Object bytes) {
        if (!(bytes instanceof byte[])) throw new IllegalArgumentException("radix2.encode input should be Uint8Array");
        return Pca.b64((byte[]) bytes);
    }

    private static BigInteger canonicalScalar(byte[] b) {
        if (!Frost.isCanonicalScalar(b)) throw new IllegalArgumentException("dkg: scalar must be 32 bytes and < the group order");
        return Frost.bytesToScalar(b);
    }

    /** The decoded commitment vector: C_0 and the bytes the challenges hash (4-byte big-endian count, then every point). */
    private static final class CommitVec {
        final EdwardsPoint c0;
        final byte[] bytes;
        CommitVec(EdwardsPoint c0, byte[] bytes) { this.c0 = c0; this.bytes = bytes; }
    }

    private static CommitVec commitVecOf(Object commitments) {
        List<Object> l = list(commitments);
        if (l == null || l.isEmpty()) throw new IllegalArgumentException("dkg: empty commitment vector");
        List<EdwardsPoint> pts = new ArrayList<>();
        for (Object c : l) pts.add(decodePoint(ub(c)));
        byte[][] parts = new byte[pts.size() + 1][];
        int n = pts.size();
        parts[0] = new byte[] { (byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n };
        for (int i = 0; i < pts.size(); i++) parts[i + 1] = pts.get(i).toBytes();
        return new CommitVec(pts.get(0), Frost.concat(parts));
    }

    private static BigInteger evalPoly(List<BigInteger> coeffs, BigInteger x) {
        BigInteger acc = BigInteger.ZERO;
        for (int j = coeffs.size() - 1; j >= 0; j--) acc = mod(acc.multiply(x).add(coeffs.get(j)));
        return acc;
    }

    private static boolean vssCheck(BigInteger share, Object commitments, Object atId) {
        List<Object> l = list(commitments);
        if (l == null) throw new IllegalArgumentException("commitments are not a list");
        if (l.isEmpty()) return false;
        EdwardsPoint lhs = Frost.mulBase(share), rhs = EdwardsPoint.ZERO;
        BigInteger x = bigId(atId), xk = BigInteger.ONE;
        for (Object cB : l) {
            rhs = rhs.add(Frost.mulPoint(decodePoint(ub(cB)), xk));
            xk = mod(xk.multiply(x));
        }
        return lhs.sameAs(rhs);
    }

    private static BigInteger popChallenge(byte[] sessionId, BigInteger identifier, CommitVec cv, EdwardsPoint r) {
        return hashToScalar(Frost.concat(CTX, DKG_POP_DST, sessionId, sb(identifier), cv.bytes, r.toBytes()));
    }

    private static BigInteger shareChallenge(byte[] sessionId, BigInteger from, BigInteger to, byte[] shareBytes, CommitVec cv, EdwardsPoint rs) {
        return hashToScalar(Frost.concat(CTX, DKG_SHARE_DST, sessionId, sb(from), sb(to), shareBytes, cv.bytes, rs.toBytes()));
    }

    private static BigInteger shareNonce(BigInteger a0, byte[] sessionId, BigInteger from, BigInteger to, byte[] shareBytes, CommitVec cv) {
        return hashToScalar(Frost.concat(CTX, DKG_SHARE_NONCE_DST, sb(a0), sessionId, sb(from), sb(to), shareBytes, cv.bytes));
    }

    private static String signShareScalar(BigInteger a0, CommitVec cv, byte[] sessionId, BigInteger from, BigInteger to, byte[] shareBytes) {
        BigInteger k = shareNonce(a0, sessionId, from, to, shareBytes, cv);
        EdwardsPoint rs = Frost.mulBase(k);
        BigInteger e = shareChallenge(sessionId, from, to, shareBytes, cv, rs);
        BigInteger s = mod(k.add(a0.multiply(e)));
        return Pca.b64(Frost.concat(rs.toBytes(), sb(s)));
    }

    private static boolean verifyShareSig(String sig, byte[] sessionId, BigInteger from, BigInteger to, byte[] shareBytes, CommitVec cv) {
        try {
            byte[] raw = ub(sig);
            if (raw.length != 64) return false;
            EdwardsPoint rs = decodePoint(java.util.Arrays.copyOfRange(raw, 0, 32));
            BigInteger s = canonicalScalar(java.util.Arrays.copyOfRange(raw, 32, 64));
            BigInteger e = shareChallenge(sessionId, from, to, shareBytes, cv, rs);
            return Frost.mulBase(s).sameAs(rs.add(Frost.mulPoint(cv.c0, e)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean verifyShareSigAgainstPackage(Object sig, byte[] sessionId, Object from, Object to, byte[] shareBytes, Map<String, Object> senderPackage) {
        try {
            if (!(sig instanceof String)) return false;
            Object cc = senderPackage.get("coefficientCommitments");
            if (cc instanceof List && ((List<?>) cc).isEmpty()) return false;
            CommitVec cv = commitVecOf(cc);
            return verifyShareSig((String) sig, sessionId, bigId(from), bigId(to), shareBytes, cv);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- state ------------------------------------------------------------------------------------------------------

    /** One participant's round-1 state: the secret polynomial coefficients stay here. */
    public static final class DkgState {
        public final long identifier;
        public final int t, n;
        public final byte[] sessionId;
        public final List<byte[]> coefficients;
        public final Map<String, Object> pkg;
        DkgState(long identifier, int t, int n, byte[] sessionId, List<byte[]> coefficients, Map<String, Object> pkg) {
            this.identifier = identifier; this.t = t; this.n = n; this.sessionId = sessionId; this.coefficients = coefficients; this.pkg = pkg;
        }
    }

    public static final class DkgRound1Result {
        public final Map<String, Object> pkg;
        public final DkgState state;
        DkgRound1Result(Map<String, Object> pkg, DkgState state) { this.pkg = pkg; this.state = state; }
    }

    private static BigInteger randomScalar(Supplier<byte[]> random) { return Frost.bytesToScalar(random.get()); }

    public static DkgRound1Result dkgRound1(Object identifier, Object t, Object n, Object sessionId, Map<String, Object> opts) { return dkgRound1(identifier, t, n, sessionId, opts, SECURE); }

    /**
     * Round 1: a random (or given) degree t-1 polynomial, its Feldman commitments and a Schnorr proof of knowledge of the constant term
     * bound to the session and identifier. {@code opts}: coefficients (t byte strings), popNonce (a fixed proof nonce, for vectors).
     */
    public static DkgRound1Result dkgRound1(Object identifier, Object t, Object n, Object sessionId, Map<String, Object> opts, Supplier<byte[]> random) {
        if (!posInteger(identifier)) throw new IllegalArgumentException("dkgRound1: identifier must be a positive integer");
        if (!isInt(t) || !isInt(n) || IntentJs.num(t) < 1 || IntentJs.num(n) < IntentJs.num(t)) throw new IllegalArgumentException("dkgRound1: need 1 <= t <= n");
        if (!(sessionId instanceof byte[]) || ((byte[]) sessionId).length == 0) throw new IllegalArgumentException("dkgRound1: sessionId must be a non-empty byte string");
        int ti = (int) (double) IntentJs.num(t), ni = (int) (double) IntentJs.num(n);
        long id = IntentJs.lng(identifier);
        byte[] sid = (byte[]) sessionId;
        List<byte[]> coeffBytes = new ArrayList<>();
        List<BigInteger> coeffs = new ArrayList<>();
        Object given = opts == null ? null : opts.get("coefficients");
        if (given != null) {
            List<Object> gl = list(given);
            if (gl == null || gl.size() != ti) throw new IllegalArgumentException("dkgRound1: coefficients.length must equal t (" + ti + ")");
            for (Object c : gl) {
                BigInteger s = Frost.bytesToScalar(bytesArg(c));
                coeffs.add(s);
                coeffBytes.add(sb(s));
            }
        } else {
            for (int j = 0; j < ti; j++) {
                BigInteger s = randomScalar(random);
                coeffs.add(s);
                coeffBytes.add(sb(s));
            }
        }
        List<Object> commitments = new ArrayList<>();
        for (BigInteger a : coeffs) commitments.add(Pca.b64(Frost.mulBase(a).toBytes()));
        BigInteger a0 = coeffs.get(0);
        CommitVec cv = commitVecOf(commitments);
        Object pn = opts == null ? null : opts.get("popNonce");
        BigInteger k = pn != null ? Frost.bytesToScalar(bytesArg(pn)) : randomScalar(random);
        EdwardsPoint r = Frost.mulBase(k);
        BigInteger c = popChallenge(sid, BigInteger.valueOf(id), cv, r);
        BigInteger mu = mod(k.add(a0.multiply(c)));
        Map<String, Object> pkg = mapOf("identifier", id, "sessionId", Pca.b64(sid), "coefficientCommitments", commitments,
            "proofOfKnowledge", mapOf("R", Pca.b64(r.toBytes()), "mu", Pca.b64(sb(mu))));
        return new DkgRound1Result(pkg, new DkgState(id, ti, ni, sid.clone(), coeffBytes, pkg));
    }

    /** Verify a round-1 package: the session matches and the proof of knowledge of C_0 holds for {@code fromIdentifier}. Never throws. */
    public static boolean dkgVerifyRound1(Object fromIdentifier, Object pkgO, Object sessionId) {
        try {
            Map<String, Object> pkg = obj(pkgO);
            if (pkg == null) return false;
            byte[] sid = bytesArg(sessionId);
            if (!Pca.b64(sid).equals(pkg.get("sessionId"))) return false;
            Object cc = pkg.get("coefficientCommitments");
            if (cc instanceof List && ((List<?>) cc).isEmpty()) return false;
            CommitVec cv = commitVecOf(cc);
            Map<String, Object> pok = obj(pkg.get("proofOfKnowledge"));
            if (pok == null) return false;
            EdwardsPoint r = decodePoint(ub(pok.get("R")));
            BigInteger mu = canonicalScalar(ub(pok.get("mu")));
            BigInteger c = popChallenge(sid, bigId(fromIdentifier), cv, r);
            return Frost.mulBase(mu).sameAs(r.add(Frost.mulPoint(cv.c0, c)));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** b64url(R_s || s): the share signature under the sender's C_0, over any share bytes. */
    public static String dkgSignShare(DkgState state, Object to, byte[] shareBytes) {
        BigInteger a0 = Frost.bytesToScalar(state.coefficients.get(0));
        CommitVec cv = commitVecOf(state.pkg.get("coefficientCommitments"));
        BigInteger toId = bigId(to);
        if (shareBytes == null) throw new IllegalArgumentException("Uint8Array expected");
        return signShareScalar(a0, cv, state.sessionId, BigInteger.valueOf(state.identifier), toId, shareBytes);
    }

    private static List<BigInteger> scalars(List<byte[]> bytes) {
        List<BigInteger> out = new ArrayList<>();
        for (byte[] b : bytes) out.add(Frost.bytesToScalar(b));
        return out;
    }

    /** Round 2: one signed share f_i(j) for every other participant in the packages, in package order. */
    public static List<Map<String, Object>> dkgRound2(DkgState state, Object allRound1Packages) {
        List<Object> pk = list(allRound1Packages);
        if (pk == null) throw new IllegalArgumentException("packages must be a list");
        List<Object> ids = new ArrayList<>();
        for (Object p : pk) {
            Map<String, Object> pm = obj(p);
            if (pm == null) throw new IllegalArgumentException("package is not an object");
            ids.add(pm.get("identifier"));
        }
        Set<Double> distinct = new HashSet<>();
        for (Object i : ids) distinct.add(key(i));
        if (distinct.size() != ids.size()) throw new IllegalArgumentException("dkgRound2: duplicate identifiers in round-1 packages");
        boolean own = false;
        for (Object i : ids) if (numEq(i, state.identifier)) own = true;
        if (!own) throw new IllegalArgumentException("dkgRound2: my own round-1 package is missing");
        String sidB64 = Pca.b64(state.sessionId);
        for (Object p : pk) {
            if (!sidB64.equals(obj(p).get("sessionId"))) throw new IllegalArgumentException("dkgRound2: participant " + AttestNvidia.jsString(obj(p).get("identifier")) + " round-1 package is from a different session");
        }
        List<BigInteger> coeffs = scalars(state.coefficients);
        BigInteger a0 = coeffs.get(0);
        CommitVec cv = commitVecOf(state.pkg.get("coefficientCommitments"));
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object j : ids) {
            if (numEq(j, state.identifier)) continue;
            BigInteger jb = bigId(j);
            byte[] share = sb(evalPoly(coeffs, jb));
            String sig = signShareScalar(a0, cv, state.sessionId, BigInteger.valueOf(state.identifier), jb, share);
            out.add(mapOf("from", state.identifier, "to", j, "sessionId", sidB64, "share", share, "sig", sig));
        }
        return out;
    }

    /** Verify a received share: the sender package is sound, the share is signed under its C_0 and satisfies the Feldman check. Never throws. */
    public static boolean dkgVerifyShare(Object receivedO, Object senderPackageO, Object myIdentifier, Object sessionId) {
        try {
            Map<String, Object> received = obj(receivedO);
            if (received == null || !(received.get("share") instanceof byte[])) return false;
            Map<String, Object> sp = obj(senderPackageO);
            if (sp == null) return false;
            if (!dkgVerifyRound1(sp.get("identifier"), sp, sessionId)) return false;
            byte[] sid = (byte[]) sessionId;
            byte[] share = (byte[]) received.get("share");
            if (!verifyShareSigAgainstPackage(received.get("sig"), sid, received.get("from"), myIdentifier, share, sp)) return false;
            return vssCheck(canonicalScalar(share), sp.get("coefficientCommitments"), myIdentifier);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * File a complaint: the accuser reveals the accused-signed share. {@code p}: accused, accuser, receivedShare (bytes), shareSig,
     * senderCommitments (unused), sessionId (bytes).
     */
    public static Map<String, Object> dkgFileComplaint(Map<String, Object> p) {
        Object accused = p.get("accused"), accuser = p.get("accuser"), shareSig = p.get("shareSig"), sessionId = p.get("sessionId");
        if (!posInteger(accused)) throw new IllegalArgumentException("dkgFileComplaint: accused must be a positive integer");
        if (!posInteger(accuser)) throw new IllegalArgumentException("dkgFileComplaint: accuser must be a positive integer");
        if (numEq(accused, accuser)) throw new IllegalArgumentException("dkgFileComplaint: cannot file a complaint against yourself");
        if (!(shareSig instanceof String) || ((String) shareSig).isEmpty()) throw new IllegalArgumentException("dkgFileComplaint: shareSig (the accused-signed share) is required");
        if (!(sessionId instanceof byte[]) || ((byte[]) sessionId).length == 0) throw new IllegalArgumentException("dkgFileComplaint: sessionId must be a non-empty byte string");
        Object received = p.get("receivedShare");
        return mapOf("accused", accused, "accuser", accuser, "sessionId", Pca.b64((byte[]) sessionId),
            "revealedShare", Pca.b64(sb(Frost.bytesToScalar(bytesArg(received)))), "shareSig", shareSig);
    }

    private static Map<String, Object> verdict(boolean justified, Object disqualify, Object atFault, String reason) {
        Map<String, Object> m = mapOf("justified", justified);
        if (disqualify != null) m.put("disqualify", disqualify);
        if (atFault != null) m.put("atFault", atFault);
        m.put("reason", reason);
        return m;
    }

    private static Map<String, Object> findPackage(List<Object> packages, Object identifier) {
        for (Object p : packages) {
            Map<String, Object> pm = obj(p);
            if (pm == null) throw new IllegalArgumentException("package is not an object");
            if (numEq(pm.get("identifier"), identifier)) return pm;
        }
        return null;
    }

    /** Adjudicate a complaint against the accused's broadcast commitments. Never throws (a malformed complaint is unjustified). */
    public static Map<String, Object> dkgVerifyComplaint(Object complaintO, Object round1Packages) {
        try {
            Map<String, Object> complaint = obj(complaintO);
            List<Object> pk = list(round1Packages);
            if (complaint == null || pk == null) throw new IllegalArgumentException("malformed");
            Map<String, Object> accusedPkg = findPackage(pk, complaint.get("accused"));
            if (accusedPkg == null) return verdict(false, null, null, "accused " + AttestNvidia.jsString(complaint.get("accused")) + " has no round-1 package to adjudicate against");
            if (!java.util.Objects.equals(accusedPkg.get("sessionId"), complaint.get("sessionId"))) {
                return verdict(false, null, null, "complaint sessionId does not match the accused round-1 package session");
            }
            byte[] sidBytes = ub(complaint.get("sessionId"));
            byte[] shareBytes = ub(complaint.get("revealedShare"));
            if (!verifyShareSigAgainstPackage(complaint.get("shareSig"), sidBytes, complaint.get("accused"), complaint.get("accuser"), shareBytes, accusedPkg)) {
                return verdict(false, null, complaint.get("accuser"), "revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)");
            }
            boolean valid = vssCheck(canonicalScalar(shareBytes), accusedPkg.get("coefficientCommitments"), complaint.get("accuser"));
            if (valid) return verdict(false, null, complaint.get("accuser"), "accused-signed share is VALID against the accused commitments — false accusation");
            return verdict(true, complaint.get("accused"), null, "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments");
        } catch (RuntimeException e) {
            return verdict(false, null, null, "malformed complaint");
        }
    }

    /** The accused answers a complaint by presenting the share it signed for the accuser. */
    public static Map<String, Object> dkgRebut(Object accused, Map<String, Object> complaint, DkgState state) {
        if (!numEq(state.identifier, accused)) throw new IllegalArgumentException("dkgRebut: myRound2State is not the accused");
        if (!numEq(complaint.get("accused"), accused)) throw new IllegalArgumentException("dkgRebut: complaint does not name this accused");
        if (!Pca.b64(state.sessionId).equals(complaint.get("sessionId"))) throw new IllegalArgumentException("dkgRebut: complaint is scoped to a different session than my state");
        List<BigInteger> coeffs = scalars(state.coefficients);
        Object accuser = complaint.get("accuser");
        byte[] share = sb(evalPoly(coeffs, bigId(accuser)));
        String shareSig = dkgSignShare(state, accuser, share);
        return mapOf("accused", accused, "accuser", accuser, "sessionId", complaint.get("sessionId"), "presentedShare", Pca.b64(share), "shareSig", shareSig);
    }

    private static Map<String, Object> blame(Object guilty, String reason) { return mapOf("guilty", guilty, "reason", reason); }

    /** Decide who is at fault in a complaint, given the accused's rebuttal (null for none). */
    public static Map<String, Object> dkgResolveBlame(Object complaintO, Object rebuttalO, Object round1Packages) {
        Map<String, Object> complaint = obj(complaintO);
        if (complaint == null) throw new IllegalArgumentException("Cannot read properties of null");
        try {
            List<Object> pk = list(round1Packages);
            if (pk == null) throw new IllegalArgumentException("packages must be a list");
            Map<String, Object> accusedPkg = findPackage(pk, complaint.get("accused"));
            if (accusedPkg == null) return blame(complaint.get("accused"), "accused " + AttestNvidia.jsString(complaint.get("accused")) + " has no round-1 package to defend with");
            if (!java.util.Objects.equals(accusedPkg.get("sessionId"), complaint.get("sessionId"))) {
                return blame(complaint.get("accuser"), "complaint names a session the accused did not run — inadmissible");
            }
            byte[] sidBytes = ub(complaint.get("sessionId"));
            byte[] shareBytes = ub(complaint.get("revealedShare"));
            boolean admissible = verifyShareSigAgainstPackage(complaint.get("shareSig"), sidBytes, complaint.get("accused"), complaint.get("accuser"), shareBytes, accusedPkg);
            if (admissible) {
                boolean valid = vssCheck(canonicalScalar(shareBytes), accusedPkg.get("coefficientCommitments"), complaint.get("accuser"));
                if (!valid) return blame(complaint.get("accused"), "accused non-repudiably signed a share that fails VSS");
                return blame(complaint.get("accuser"), "accused-signed share is valid against its commitments — false accusation");
            }
            Map<String, Object> rebuttal = obj(rebuttalO);
            if (rebuttal != null && numEq(rebuttal.get("accused"), complaint.get("accused")) && numEq(rebuttal.get("accuser"), complaint.get("accuser"))
                && java.util.Objects.equals(rebuttal.get("sessionId"), complaint.get("sessionId"))) {
                byte[] rShare = ub(rebuttal.get("presentedShare"));
                boolean rebuttalValid = verifyShareSigAgainstPackage(rebuttal.get("shareSig"), sidBytes, complaint.get("accused"), complaint.get("accuser"), rShare, accusedPkg)
                    && vssCheck(canonicalScalar(rShare), accusedPkg.get("coefficientCommitments"), complaint.get("accuser"));
                if (rebuttalValid) {
                    return blame(complaint.get("accuser"), "accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted");
                }
                return blame(complaint.get("accused"), "accused could not present a validly-signed, VSS-correct share on rebuttal");
            }
            return blame(complaint.get("accuser"), "complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused");
        } catch (RuntimeException e) {
            return blame(complaint.get("accuser"), "malformed complaint — inadmissible");
        }
    }

    /** The qualified set: participants with a sound round-1 package in the plurality session, minus the guilty of every complaint. Ascending. */
    public static List<Object> dkgQualifiedSet(Object participants, Object complaints, Object round1Packages, Object rebuttals) {
        List<Object> pk = list(round1Packages), ps = list(participants), cs = list(complaints);
        List<Object> rbs = rebuttals == null ? new ArrayList<>() : list(rebuttals);
        if (pk == null || ps == null || cs == null || rbs == null) throw new IllegalArgumentException("arguments must be lists");
        Map<Double, Map<String, Object>> pkgById = new HashMap<>();
        for (Object p : pk) { Map<String, Object> pm = obj(p); if (pm == null) throw new IllegalArgumentException("package is not an object"); pkgById.put(key(pm.get("identifier")), pm); }
        Map<Object, Integer> sessionCounts = new LinkedHashMap<>();
        for (Object p : pk) sessionCounts.merge(obj(p).get("sessionId"), 1, Integer::sum);
        Object runSession = "";
        int best = -1;
        for (Map.Entry<Object, Integer> e : sessionCounts.entrySet()) {
            if (e.getValue() > best) { best = e.getValue(); runSession = e.getKey(); }
        }
        Set<Double> qualified = new LinkedHashSet<>();
        for (Object p : ps) {
            Map<String, Object> pkg = pkgById.get(key(p));
            if (pkg == null) continue;
            if (!java.util.Objects.equals(pkg.get("sessionId"), runSession)) continue;
            byte[] sid;
            try { sid = ub(pkg.get("sessionId")); } catch (RuntimeException e) { continue; }
            if (dkgVerifyRound1(p, pkg, sid)) qualified.add(key(p));
        }
        for (Object co : cs) {
            Map<String, Object> c = obj(co);
            Object reb = null;
            for (Object r : rbs) {
                Map<String, Object> rm = obj(r);
                if (rm == null) throw new IllegalArgumentException("rebuttal is not an object");
                if (c != null && numEq(rm.get("accused"), c.get("accused")) && numEq(rm.get("accuser"), c.get("accuser"))
                    && java.util.Objects.equals(rm.get("sessionId"), c.get("sessionId"))) { reb = rm; break; }
            }
            Map<String, Object> res = dkgResolveBlame(co, reb, pk);
            if (c != null && numEq(res.get("guilty"), c.get("accused"))) qualified.remove(key(res.get("guilty")));
        }
        List<Double> sorted = new ArrayList<>(qualified);
        Collections.sort(sorted);
        List<Object> out = new ArrayList<>();
        for (Double d : sorted) out.add((long) (double) d);
        return out;
    }

    // ---- transcript digest and echo agreement ----------------------------------------------------------------------

    private static Object u(Map<String, Object> m, String k) { return m.containsKey(k) ? m.get(k) : FrostNet.UNDEFINED; }

    private static String round1PackageDigest(Object po) {
        Map<String, Object> p = obj(po);
        Map<String, Object> pok = obj(p.get("proofOfKnowledge"));
        return Pca.hashCanonical(mapOf("identifier", u(p, "identifier"), "sessionId", u(p, "sessionId"), "coefficientCommitments", u(p, "coefficientCommitments"),
            "proofOfKnowledge", mapOf("R", u(pok, "R"), "mu", u(pok, "mu"))));
    }

    private static String complaintDigest(Object co) {
        Map<String, Object> c = obj(co);
        return Pca.hashCanonical(mapOf("accused", u(c, "accused"), "accuser", u(c, "accuser"), "sessionId", u(c, "sessionId"),
            "revealedShare", u(c, "revealedShare"), "shareSig", u(c, "shareSig")));
    }

    private static List<Object> sortedIds(Object qualified) {
        List<Object> q = list(qualified);
        if (q == null) throw new IllegalArgumentException("qualified must be a list");
        List<Double> d = new ArrayList<>();
        for (Object x : q) d.add(IntentJs.num(x));
        Collections.sort(d, (a, b) -> Double.compare(a, b));
        List<Object> out = new ArrayList<>();
        for (Double x : d) out.add((long) (double) x);
        return out;
    }

    /** The digest of a party's whole view: sorted package digests, sorted complaint digests, the qualified set and the session. */
    public static String dkgTranscriptDigest(Map<String, Object> args) {
        List<String> round1 = new ArrayList<>(), complaints = new ArrayList<>();
        for (Object p : list(args.get("round1Packages"))) round1.add(round1PackageDigest(p));
        for (Object c : list(args.get("complaints"))) complaints.add(complaintDigest(c));
        Collections.sort(round1);
        Collections.sort(complaints);
        return Pca.hashCanonical(mapOf("sessionId", b64u(args.get("sessionId")), "round1", new ArrayList<Object>(round1),
            "complaints", new ArrayList<Object>(complaints), "qualified", sortedIds(args.get("qualified"))));
    }

    /** A party's echo of its transcript view. {@code args}: identifier, round1Packages, complaints, qualified, sessionId. */
    public static Map<String, Object> dkgEcho(Map<String, Object> args) {
        return mapOf("identifier", args.get("identifier"), "sessionId", b64u(args.get("sessionId")), "transcriptDigest", dkgTranscriptDigest(args));
    }

    private static Map<String, Object> agreement(boolean agreed, String digest, String reason) {
        Map<String, Object> m = mapOf("agreed", agreed);
        if (digest != null) m.put("digest", digest);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /** Check that every qualified participant echoed the same transcript digest for this session. Never throws. */
    public static Map<String, Object> dkgCheckEchoes(Object qualified, Object echoes, Object sessionId) {
        try {
            String sidB64 = b64u(sessionId);
            List<Object> q = list(qualified), es = list(echoes);
            if (q == null || es == null) throw new IllegalArgumentException("malformed");
            Set<Double> qSet = new LinkedHashSet<>();
            for (Object x : q) qSet.add(key(x));
            Map<Double, Map<String, Object>> byId = new HashMap<>();
            for (Object eo : es) {
                Map<String, Object> e = obj(eo);
                if (e == null) throw new IllegalArgumentException("echo is not an object");
                Double id = key(e.get("identifier"));
                if (!qSet.contains(id)) continue;
                if (!sidB64.equals(e.get("sessionId"))) return agreement(false, null, "echo from " + AttestNvidia.jsString(e.get("identifier")) + " is bound to a different session");
                if (byId.containsKey(id)) return agreement(false, null, "duplicate echo from qualified participant " + AttestNvidia.jsString(e.get("identifier")));
                byId.put(id, e);
            }
            Object agreed = null;
            boolean have = false;
            for (Double j : qSet) {
                Map<String, Object> e = byId.get(j);
                if (e == null) return agreement(false, null, "missing echo from qualified participant " + AttestNvidia.jsString(j == null ? (Object) "undefined" : (Object) j));
                if (!have) {
                    agreed = e.get("transcriptDigest");
                    have = agreed != null;
                } else if (!java.util.Objects.equals(e.get("transcriptDigest"), agreed)) {
                    return agreement(false, null, "qualified participant " + AttestNvidia.jsString(j) + " echoed a DIFFERENT transcript (equivocation detected)");
                }
            }
            if (!have) return agreement(false, null, "no qualified echoes to agree on");
            Map<String, Object> m = mapOf("agreed", true, "digest", agreed);
            return m;
        } catch (RuntimeException e) {
            return agreement(false, null, "malformed echoes");
        }
    }

    // ---- finalize -------------------------------------------------------------------------------------------------------

    /**
     * Finalize: the signing share (own f_i(i) plus every qualified sender's share), the group key and commitment, and every qualified
     * participant's verifying share. {@code qualified} (null = everyone) and {@code agreement} ({echoes, complaints?}) are optional;
     * with echoes the agreed transcript digest must equal this party's own view.
     */
    public static Map<String, Object> dkgFinalize(Object myIdentifier, DkgState myState, Object receivedShares, Object allCommitments, Object qualified, Map<String, Object> agreement) {
        if (!numEq(myState.identifier, myIdentifier)) throw new IllegalArgumentException("dkgFinalize: myState.identifier != myIdentifier");
        List<Object> pk = list(allCommitments);
        if (pk == null) throw new IllegalArgumentException("packages must be a list");
        List<Object> ids = new ArrayList<>();
        for (Object p : pk) { Map<String, Object> pm = obj(p); if (pm == null) throw new IllegalArgumentException("package is not an object"); ids.add(pm.get("identifier")); }
        Set<Double> idSet = new HashSet<>();
        for (Object i : ids) idSet.add(key(i));
        if (idSet.size() != ids.size()) throw new IllegalArgumentException("dkgFinalize: duplicate identifiers in commitments");
        if (!idSet.contains(key(myIdentifier))) throw new IllegalArgumentException("dkgFinalize: my own package is missing from allCommitments");
        String sidB64 = Pca.b64(myState.sessionId);
        for (Object p : pk) {
            if (!sidB64.equals(obj(p).get("sessionId"))) throw new IllegalArgumentException("dkgFinalize: participant " + AttestNvidia.jsString(obj(p).get("identifier")) + " round-1 package is from a different session");
        }
        List<Object> qIn = qualified == null ? ids : list(qualified);
        if (qIn == null) throw new IllegalArgumentException("qualified must be a list");
        List<Object> qset = new ArrayList<>();
        for (Object id : qIn) if (idSet.contains(key(id))) qset.add(id);
        Set<Double> qSet = new LinkedHashSet<>();
        for (Object id : qset) qSet.add(key(id));
        if (!qSet.contains(key(myIdentifier))) throw new IllegalArgumentException("dkgFinalize: myIdentifier is not in the qualified set");
        if (qSet.size() < myState.t) throw new IllegalArgumentException("dkgFinalize: qualified set (" + qSet.size() + ") is smaller than the threshold t=" + myState.t);
        int t = myState.t;
        for (Object p : pk) {
            Map<String, Object> pm = obj(p);
            if (!qSet.contains(key(pm.get("identifier")))) continue;
            List<Object> cc = list(pm.get("coefficientCommitments"));
            if (cc == null || cc.size() != t) throw new IllegalArgumentException("dkgFinalize: participant " + AttestNvidia.jsString(pm.get("identifier")) + " committed to a different number of coefficients than t=" + t);
        }
        if (agreement != null && agreement.containsKey("echoes")) {
            List<Double> qs = new ArrayList<>(qSet);
            Collections.sort(qs);
            List<Object> qsorted = new ArrayList<>();
            for (Double d : qs) qsorted.add((long) (double) d);
            Map<String, Object> check = dkgCheckEchoes(qsorted, agreement.get("echoes"), myState.sessionId);
            if (!Boolean.TRUE.equals(check.get("agreed"))) throw new IllegalArgumentException("dkgFinalize: echo-broadcast agreement failed — " + check.get("reason"));
            Object cplx = agreement.get("complaints");
            String mine = dkgTranscriptDigest(mapOf("round1Packages", pk, "complaints", cplx == null ? new ArrayList<Object>() : cplx, "qualified", qsorted, "sessionId", myState.sessionId));
            if (!mine.equals(check.get("digest"))) throw new IllegalArgumentException("dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)");
        }
        Map<Double, byte[]> recvBy = new LinkedHashMap<>();
        List<Object> rs = list(receivedShares);
        if (rs == null) throw new IllegalArgumentException("receivedShares must be a list");
        for (Object ro : rs) {
            Map<String, Object> r = obj(ro);
            if (r == null) throw new IllegalArgumentException("received share is not an object");
            if (numEq(r.get("from"), myIdentifier)) continue;
            if (!qSet.contains(key(r.get("from")))) continue;
            if (!sidB64.equals(r.get("sessionId"))) throw new IllegalArgumentException("dkgFinalize: received share from " + AttestNvidia.jsString(r.get("from")) + " is from a different session");
            if (recvBy.containsKey(key(r.get("from")))) throw new IllegalArgumentException("dkgFinalize: duplicate received share from " + AttestNvidia.jsString(r.get("from")));
            recvBy.put(key(r.get("from")), bytesArg(r.get("share")));
        }
        for (Object j : qset) {
            if (numEq(j, myIdentifier)) continue;
            if (!recvBy.containsKey(key(j))) throw new IllegalArgumentException("dkgFinalize: missing received share from qualified participant " + AttestNvidia.jsString(j));
        }
        List<BigInteger> myCoeffs = scalars(myState.coefficients);
        BigInteger sSum = evalPoly(myCoeffs, bigId(myIdentifier));
        for (byte[] share : recvBy.values()) {
            if (share.length == 0) throw new IllegalArgumentException("ct-scalar: reduce takes 1..64 bytes");
            sSum = mod(sSum.add(Frost.bytesToScalar(share)));
        }
        byte[] signingShare = sb(sSum);
        List<EdwardsPoint> groupCoeffPoints = new ArrayList<>();
        for (int k = 0; k < t; k++) {
            EdwardsPoint acc = EdwardsPoint.ZERO;
            for (Object p : pk) {
                Map<String, Object> pm = obj(p);
                if (!qSet.contains(key(pm.get("identifier")))) continue;
                acc = acc.add(decodePoint(ub(list(pm.get("coefficientCommitments")).get(k))));
            }
            groupCoeffPoints.add(acc);
        }
        byte[] groupPublicKey = groupCoeffPoints.get(0).toBytes();
        List<Object> groupCommitment = new ArrayList<>();
        for (EdwardsPoint pt : groupCoeffPoints) groupCommitment.add(pt.toBytes());
        List<Object> verifyingShares = new ArrayList<>();
        Map<String, Object> mine = null;
        for (Object j : qset) {
            EdwardsPoint acc = EdwardsPoint.ZERO;
            BigInteger x = bigId(j), xk = BigInteger.ONE;
            for (EdwardsPoint phi : groupCoeffPoints) {
                acc = acc.add(Frost.mulPoint(phi, xk));
                xk = mod(xk.multiply(x));
            }
            Map<String, Object> v = mapOf("identifier", j, "publicKey", acc.toBytes());
            verifyingShares.add(v);
            if (mine == null && numEq(j, myIdentifier)) mine = v;
        }
        BigInteger s = Frost.bytesToScalar(signingShare);
        byte[] verifyingShare = Frost.mulBase(s).toBytes();
        if (mine == null || !Frost.mulBase(s).sameAs(decodePoint((byte[]) mine.get("publicKey")))) {
            throw new IllegalArgumentException("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)");
        }
        return mapOf("identifier", myIdentifier, "signingShare", signingShare, "groupPublicKey", groupPublicKey, "verifyingShare", verifyingShare,
            "publicKeyPackage", mapOf("groupPublicKey", groupPublicKey, "groupCommitment", groupCommitment, "verifyingShares", verifyingShares));
    }

    // ---- simulation ------------------------------------------------------------------------------------------------------

    public static Map<String, Object> frostDkgSimulate(Object t, Object n, Map<String, Object> opts) { return frostDkgSimulate(t, n, opts, SECURE); }

    /**
     * Run a whole ceremony in-process (for tests and demos). {@code opts}: identifiers, coefficientsByParticipant, sessionId, cheaters
     * (their shares are made inconsistent with their commitments), equivocateEchoFor (that party echoes a different qualified set).
     */
    public static Map<String, Object> frostDkgSimulate(Object tO, Object nO, Map<String, Object> opts, Supplier<byte[]> random) {
        if (!isInt(tO) || !isInt(nO) || IntentJs.num(tO) < 1 || IntentJs.num(nO) < IntentJs.num(tO)) throw new IllegalArgumentException("frostDkgSimulate: need 1 <= t <= n");
        int t = (int) (double) IntentJs.num(tO), n = (int) (double) IntentJs.num(nO);
        if (opts == null) opts = new LinkedHashMap<>();
        List<Object> ids = new ArrayList<>();
        if (opts.get("identifiers") != null) {
            List<Object> given = list(opts.get("identifiers"));
            if (given == null) throw new IllegalArgumentException("identifiers must be a list");
            ids.addAll(given);
        } else for (int i = 0; i < n; i++) ids.add((long) (i + 1));
        if (ids.size() != n) throw new IllegalArgumentException("frostDkgSimulate: identifiers.length must equal n");
        Set<Double> distinct = new HashSet<>();
        for (Object i : ids) distinct.add(key(i));
        if (distinct.size() != n) throw new IllegalArgumentException("frostDkgSimulate: identifiers must be distinct");
        for (Object i : ids) if (!posInteger(i)) throw new IllegalArgumentException("frostDkgSimulate: identifiers must be positive integers");
        byte[] sessionId = opts.get("sessionId") != null ? bytesArg(opts.get("sessionId")) : random.get();
        Set<Double> cheaters = new HashSet<>();
        if (opts.get("cheaters") != null) for (Object c : list(opts.get("cheaters"))) cheaters.add(key(c));
        List<Object> perParticipant = opts.get("coefficientsByParticipant") == null ? null : list(opts.get("coefficientsByParticipant"));
        List<DkgState> states = new ArrayList<>();
        for (int idx = 0; idx < ids.size(); idx++) {
            Map<String, Object> o = new LinkedHashMap<>();
            if (perParticipant != null && idx < perParticipant.size()) o.put("coefficients", perParticipant.get(idx));
            states.add(dkgRound1(ids.get(idx), t, n, sessionId, o, random).state);
        }
        List<Object> round1Packages = new ArrayList<>();
        for (DkgState st : states) round1Packages.add(st.pkg);
        for (Object p : round1Packages) {
            if (!dkgVerifyRound1(obj(p).get("identifier"), p, sessionId)) throw new IllegalStateException("frostDkgSimulate: PoP verification failed for participant " + AttestNvidia.jsString(obj(p).get("identifier")));
        }
        Map<Double, List<Object>> inbox = new LinkedHashMap<>();
        for (Object i : ids) inbox.put(key(i), new ArrayList<>());
        List<Object> complaints = new ArrayList<>();
        Map<Double, DkgState> stateById = new HashMap<>();
        for (DkgState st : states) stateById.put((double) st.identifier, st);
        for (DkgState st : states) {
            for (Map<String, Object> outgoing : dkgRound2(st, round1Packages)) {
                byte[] shareBytes = (byte[]) outgoing.get("share");
                Object shareSig = outgoing.get("sig");
                if (cheaters.contains(key(outgoing.get("from")))) {
                    byte[] bad = shareBytes.clone();
                    bad[0] = (byte) (bad[0] ^ 0x01);
                    shareBytes = bad;
                    shareSig = dkgSignShare(st, outgoing.get("to"), bad);
                }
                Map<String, Object> senderPkg = null;
                for (Object p : round1Packages) if (numEq(obj(p).get("identifier"), outgoing.get("from"))) { senderPkg = obj(p); break; }
                if (dkgVerifyShare(mapOf("from", outgoing.get("from"), "share", shareBytes, "sig", shareSig), senderPkg, outgoing.get("to"), sessionId)) {
                    inbox.get(key(outgoing.get("to"))).add(mapOf("from", outgoing.get("from"), "sessionId", outgoing.get("sessionId"), "share", shareBytes, "sig", shareSig));
                } else {
                    complaints.add(dkgFileComplaint(mapOf("accused", outgoing.get("from"), "accuser", outgoing.get("to"), "receivedShare", shareBytes, "shareSig", shareSig,
                        "senderCommitments", senderPkg.get("coefficientCommitments"), "sessionId", sessionId)));
                }
            }
        }
        List<Object> rebuttals = new ArrayList<>();
        for (Object co : complaints) {
            Map<String, Object> c = obj(co);
            rebuttals.add(dkgRebut(c.get("accused"), c, stateById.get(key(c.get("accused")))));
        }
        List<Object> qualified = dkgQualifiedSet(ids, complaints, round1Packages, rebuttals);
        if (qualified.size() < t) throw new IllegalStateException("frostDkgSimulate: only " + qualified.size() + " qualified participants (< t=" + t + ") after the blame round");
        Object equivocator = opts.get("equivocateEchoFor");
        List<Object> echoes = new ArrayList<>();
        for (Object id : qualified) {
            List<Object> view = qualified;
            if (equivocator != null && numEq(id, equivocator)) {
                view = new ArrayList<>();
                Object last = qualified.get(qualified.size() - 1);
                for (Object q : qualified) if (!numEq(q, last)) view.add(q);
            }
            echoes.add(dkgEcho(mapOf("identifier", id, "round1Packages", round1Packages, "complaints", complaints, "qualified", view, "sessionId", sessionId)));
        }
        List<Object> keyPackages = new ArrayList<>();
        for (DkgState st : states) {
            boolean in = false;
            for (Object q : qualified) if (numEq(q, st.identifier)) in = true;
            if (!in) continue;
            keyPackages.add(dkgFinalize(st.identifier, st, inbox.get((double) st.identifier), round1Packages, qualified, mapOf("echoes", echoes, "complaints", complaints)));
        }
        byte[] groupPublicKey = (byte[]) obj(keyPackages.get(0)).get("groupPublicKey");
        for (Object kp : keyPackages) {
            if (!Pca.b64((byte[]) obj(kp).get("groupPublicKey")).equals(Pca.b64(groupPublicKey))) throw new IllegalStateException("frostDkgSimulate: participants disagree on the group public key");
        }
        List<Object> participantShares = new ArrayList<>();
        for (Object kp : keyPackages) participantShares.add(mapOf("identifier", obj(kp).get("identifier"), "share", obj(kp).get("signingShare"), "publicKey", obj(kp).get("verifyingShare")));
        return mapOf("groupPublicKey", groupPublicKey, "participantShares", participantShares,
            "groupCommitment", obj(obj(keyPackages.get(0)).get("publicKeyPackage")).get("groupCommitment"), "keyPackages", keyPackages,
            "round1Packages", round1Packages, "qualified", qualified, "complaints", complaints, "rebuttals", rebuttals, "echoes", echoes, "sessionId", sessionId);
    }
}
