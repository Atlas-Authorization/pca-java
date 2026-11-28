package net.atlasauth.pca;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Frost.FrostCommitResult;
import net.atlasauth.pca.Frost.FrostCommitment;
import net.atlasauth.pca.Frost.FrostKeygenOpts;
import net.atlasauth.pca.Frost.FrostKeygenResult;
import net.atlasauth.pca.Frost.FrostNonces;
import net.atlasauth.pca.Frost.FrostParticipantShare;
import net.atlasauth.pca.Frost.FrostSignOpts;
import net.atlasauth.pca.Frost.FrostSignatureShare;
import net.atlasauth.pca.Frost.VerificationShare;
import org.junit.jupiter.api.Test;

/** Replays the reference FROST oracle (deterministic nonces, keys and messages) through the native implementation. */
class FrostDiffTest {
    private static final String M = "ref-core-frost-java";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("expected object");
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("expected array");
        return (List<Object>) o;
    }

    private static byte[] by(Object o) {
        if (o instanceof Map && ((Map<?, ?>) o).size() == 1 && ((Map<?, ?>) o).get("$bytes") instanceof String) return Keys.unb64u((String) ((Map<?, ?>) o).get("$bytes"));
        throw new IllegalArgumentException("expected bytes");
    }

    private static byte[] byOrNull(Object o) { return o == null ? null : by(o); }

    /** A JSON number that is a whole number (the reference refuses anything else as an identifier / count). */
    private static long whole(Object o) {
        if (!(o instanceof Json.Num)) throw new IllegalArgumentException("expected number");
        BigDecimal d = new BigDecimal(((Json.Num) o).raw);
        if (d.stripTrailingZeros().scale() > 0) throw new IllegalArgumentException("expected integer");
        return d.toBigIntegerExact().longValueExact();
    }

    private static int whole32(Object o) {
        long v = whole(o);
        if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) throw new IllegalArgumentException("out of range");
        return (int) v;
    }

    private static FrostCommitment commitment(Object o) { Map<String, Object> m = map(o); return new FrostCommitment(whole(m.get("identifier")), by(m.get("hiding")), by(m.get("binding"))); }

    private static List<FrostCommitment> commitments(Object o) {
        if (o == null) return null;
        List<FrostCommitment> out = new ArrayList<>();
        for (Object c : list(o)) out.add(commitment(c));
        return out;
    }

    private static List<VerificationShare> vshares(Object o) {
        if (o == null) return null;
        List<VerificationShare> out = new ArrayList<>();
        for (Object v : list(o)) { Map<String, Object> m = map(v); out.add(new VerificationShare(whole(m.get("identifier")), by(m.get("publicKey")))); }
        return out;
    }

    private static FrostSignatureShare sigShare(Object o) { Map<String, Object> m = map(o); return new FrostSignatureShare(whole(m.get("identifier")), by(m.get("sigShare"))); }

    private static List<FrostSignatureShare> sigShares(Object o) {
        if (o == null) return null;
        List<FrostSignatureShare> out = new ArrayList<>();
        for (Object s : list(o)) out.add(sigShare(s));
        return out;
    }

    private static Map<String, Object> commitmentOut(FrostCommitment c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("identifier", c.identifier); m.put("hiding", c.hiding); m.put("binding", c.binding);
        return m;
    }

    private static Map<String, Object> keygenOut(FrostKeygenResult kg) {
        Map<String, Object> m = new LinkedHashMap<>();
        List<Object> shares = new ArrayList<>();
        for (FrostParticipantShare s : kg.participantShares) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("identifier", s.identifier); e.put("share", s.share); e.put("publicKey", s.publicKey);
            shares.add(e);
        }
        m.put("groupPublicKey", kg.groupPublicKey); m.put("participantShares", shares); m.put("groupCommitment", new ArrayList<Object>(kg.groupCommitment));
        return m;
    }

    private static FrostKeygenResult keygen(Map<String, Object> a) {
        FrostKeygenOpts o = new FrostKeygenOpts();
        o.secret = byOrNull(a.get("secret"));
        if (a.get("coefficients") != null) { o.coefficients = new ArrayList<>(); for (Object c : list(a.get("coefficients"))) o.coefficients.add(by(c)); }
        if (a.get("identifiers") != null) { List<Object> ids = list(a.get("identifiers")); o.identifiers = new long[ids.size()]; for (int i = 0; i < ids.size(); i++) o.identifiers[i] = whole(ids.get(i)); }
        return Frost.trustedDealerKeygen(whole32(a.get("t")), whole32(a.get("n")), o);
    }

    private static FrostSignOpts signOpts(Object o) {
        FrostSignOpts s = new FrostSignOpts();
        if (o == null) return s;
        Map<String, Object> m = map(o);
        if (m.get("threshold") != null) s.threshold = whole32(m.get("threshold"));
        s.verificationShare = byOrNull(m.get("verificationShare"));
        s.verificationShares = vshares(m.get("verificationShares"));
        return s;
    }

    @Test void genCorpusIsPresent() { BaseOracle.requireGen(M); }

    @Test void scalar() throws Exception { OracleCases.each(M, "scalar", a -> Frost.scalarToBytes(Frost.bytesToScalar(by(a.get(0))))); }

    @Test void isCanonicalScalar() throws Exception {
        OracleCases.each(M, "isCanonicalScalar", a -> a.get(0) != null && Frost.isCanonicalScalar(by(a.get(0))));
    }

    @Test void hash() throws Exception {
        OracleCases.each(M, "hash", a -> {
            byte[] m = by(a.get(1));
            switch ((String) a.get(0)) {
                case "H1": return Frost.scalarToBytes(Frost.H1(m));
                case "H2": return Frost.scalarToBytes(Frost.H2(m));
                case "H3": return Frost.scalarToBytes(Frost.H3(m));
                case "H4": return Frost.H4(m);
                case "H5": return Frost.H5(m);
                default: throw new IllegalArgumentException("unknown hash");
            }
        });
    }

    @Test void decodeSafePoint() throws Exception { OracleCases.each(M, "decodeSafePoint", a -> Frost.decodeSafePoint(byOrNull(a.get(0))).toBytes()); }

    @Test void keygen() throws Exception { OracleCases.each(M, "keygen", a -> keygenOut(keygen(map(a.get(0))))); }

    @Test void verifyingShare() throws Exception { OracleCases.each(M, "verifyingShare", a -> Frost.verifyingShare(by(a.get(0)))); }

    @Test void commit() throws Exception {
        OracleCases.each(M, "commit", a -> {
            FrostCommitResult c = Frost.commit(new FrostParticipantShare(whole(a.get(0)), by(a.get(1)), new byte[32]), by(a.get(2)), by(a.get(3)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("hidingNonce", c.hidingNonce); m.put("bindingNonce", c.bindingNonce); m.put("commitment", commitmentOut(c.commitment));
            return m;
        });
    }

    @Test void flow() throws Exception {
        OracleCases.each(M, "flow", a -> {
            Map<String, Object> in = map(a.get(0));
            FrostKeygenResult kg = keygen(in);
            Map<Long, FrostParticipantShare> byId = new LinkedHashMap<>();
            for (FrostParticipantShare s : kg.participantShares) byId.put(s.identifier, s);
            List<FrostParticipantShare> quorum = new ArrayList<>();
            for (Object id : list(in.get("signers"))) {
                FrostParticipantShare p = byId.get(whole(id));
                if (p == null) throw new IllegalArgumentException("unknown signer");
                quorum.add(p);
            }
            List<Object> rnd = list(in.get("randomness"));
            List<FrostCommitResult> commits = new ArrayList<>();
            List<FrostCommitment> cs = new ArrayList<>();
            List<VerificationShare> vss = new ArrayList<>();
            for (int i = 0; i < quorum.size(); i++) {
                Map<String, Object> r = map(rnd.get(i));
                FrostCommitResult c = Frost.commit(quorum.get(i), by(r.get("hr")), by(r.get("br")));
                commits.add(c); cs.add(c.commitment);
                vss.add(new VerificationShare(quorum.get(i).identifier, quorum.get(i).publicKey));
            }
            Integer thr = in.get("threshold") == null ? null : whole32(in.get("threshold"));
            byte[] msg = by(in.get("message"));
            List<FrostSignatureShare> shares = new ArrayList<>();
            for (int i = 0; i < quorum.size(); i++) {
                FrostSignOpts o = new FrostSignOpts();
                o.threshold = thr; o.verificationShare = quorum.get(i).publicKey; o.verificationShares = vss;
                shares.add(Frost.sign(quorum.get(i).identifier, quorum.get(i).share, kg.groupPublicKey, commits.get(i).nonces(), msg, cs, o));
            }
            byte[] agg = Frost.aggregate(msg, cs, shares, kg.groupPublicKey, thr, vss);
            Map<String, Object> out = keygenOut(kg);
            List<Object> cOut = new ArrayList<>(), sOut = new ArrayList<>();
            for (FrostCommitment c : cs) cOut.add(commitmentOut(c));
            for (FrostSignatureShare s : shares) { Map<String, Object> e = new LinkedHashMap<>(); e.put("identifier", s.identifier); e.put("sigShare", s.sigShare); sOut.add(e); }
            out.put("commitments", cOut); out.put("sigShares", sOut); out.put("aggregate", agg);
            return out;
        });
    }

    @Test void sign() throws Exception {
        OracleCases.each(M, "sign", a -> {
            long id = whole(a.get(0));
            byte[] share = by(a.get(1)), group = by(a.get(2));
            FrostNonces nonces = null;
            if (a.get(3) != null) { Map<String, Object> n = map(a.get(3)); nonces = new FrostNonces(byOrNull(n.get("hiding")), byOrNull(n.get("binding"))); }
            if (nonces != null && (nonces.hiding == null || nonces.binding == null)) throw new IllegalArgumentException("malformed nonces");
            FrostSignatureShare s = Frost.sign(id, share, group, nonces, by(a.get(4)), commitments(a.get(5)), signOpts(a.get(6)));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("identifier", s.identifier); m.put("sigShare", s.sigShare);
            return m;
        });
    }

    @Test void aggregate() throws Exception {
        OracleCases.each(M, "aggregate", a -> {
            Map<String, Object> o = map(a.get(4));
            Integer thr = o.get("threshold") == null ? null : whole32(o.get("threshold"));
            return Frost.aggregate(by(a.get(0)), commitments(a.get(1)), sigShares(a.get(2)), byOrNull(a.get(3)), thr, vshares(o.get("verificationShares")));
        });
    }

    @Test void verifySigShare() throws Exception {
        OracleCases.each(M, "verifySigShare", a -> {
            try {
                Map<String, Object> p = map(a.get(0));
                return Frost.verifySigShare(whole(p.get("identifier")), by(p.get("publicKey")), commitment(p.get("commitment")), sigShare(p.get("sigShare")),
                    commitments(p.get("signingCommitments")), by(p.get("groupPublicKey")), by(p.get("message")));
            } catch (RuntimeException e) {
                return false;
            }
        });
    }

    @Test void cosign() throws Exception {
        OracleCases.each(M, "cosign", a -> {
            byte[] group = by(a.get(0)), msg = by(a.get(2));
            List<FrostParticipantShare> quorum = null;
            if (a.get(1) != null) {
                quorum = new ArrayList<>();
                for (Object q : list(a.get(1))) { Map<String, Object> m = map(q); quorum.add(new FrostParticipantShare(whole(m.get("identifier")), by(m.get("share")), by(m.get("publicKey")))); }
            }
            Map<String, Object> o = map(a.get(3));
            byte[] sig = Frost.cosign(group, quorum, msg, o.get("threshold") == null ? null : whole32(o.get("threshold")));
            return EdStrict.verify(group, msg, sig);
        });
    }
}
