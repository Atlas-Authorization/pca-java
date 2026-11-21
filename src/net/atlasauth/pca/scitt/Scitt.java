package net.atlasauth.pca.scitt;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * SCITT transparency receipts for Proof-Carrying Authority (RFC 9943 SCITT architecture + RFC 9942 COSE Receipts). A verified PCActn is
 * registered as a COSE Signed Statement (a COSE_Sign1 over the canonical PCActn), appended to an append-only RFC 9162 Merkle log, and
 * handed back a COSE Receipt: a COSE_Sign1 signed by the Transparency Service carrying an inclusion proof against the log root.
 * Port of {@code @atlasauth/pca-scitt}: the same bytes for the same inputs (Ed25519 and the ES256 low-S normalisation).
 *
 * <p>Keys are JDK {@link PrivateKey} / {@link PublicKey} (Ed25519 or P-256). An inclusion proof is the JSON-shaped map
 * {@code {index, size, path: [{side: "L"|"R", hash: b64u}]}} used by the core ledger.
 */
public final class Scitt {
    private Scitt() {}

    public static final int COSE_SIGN1_TAG = 18;
    public static final int HDR_ALG = 1;
    public static final int HDR_CONTENT_TYPE = 3;
    public static final int HDR_CWT_CLAIMS = 15;
    public static final int CWT_ISS = 1;
    public static final int CWT_SUB = 2;
    public static final int HDR_VDS = 395;
    public static final int HDR_VDS_PROOFS = 396;
    public static final int VDS_RFC9162_SHA256 = 1;
    public static final int PROOF_TYPE_INCLUSION = -1;
    public static final String DEFAULT_CONTENT_TYPE = "application/pca+json";

    public enum CoseAlg {
        EdDSA(-8), ES256(-7);

        final long label;

        CoseAlg(long label) { this.label = label; }
    }

    private static IllegalArgumentException err(String m) { return new IllegalArgumentException(m); }

    private static CoseAlg algForLabel(long label) {
        if (label == -8) return CoseAlg.EdDSA;
        if (label == -7) return CoseAlg.ES256;
        return null;
    }

    // ---- key helpers (JDK keys) ----

    private static final byte[] ED_PKCS8 = hex("302e020100300506032b657004220420");
    private static final byte[] ED_SPKI = hex("302a300506032b6570032100");

    private static byte[] cat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    private static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    /** The Ed25519 private key for a 32-byte seed. */
    public static PrivateKey ed25519PrivateKey(byte[] seed) {
        if (seed == null || seed.length != 32) throw err("an Ed25519 seed is 32 bytes");
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(cat(ED_PKCS8, seed)));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The Ed25519 public key for a 32-byte raw key. */
    public static PublicKey ed25519PublicKey(byte[] raw) {
        if (raw == null || raw.length != 32) throw err("an Ed25519 public key is 32 bytes");
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(cat(ED_SPKI, raw)));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ECParameterSpec p256() throws java.security.GeneralSecurityException {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    /** The P-256 public key for affine coordinates (32-byte big-endian x and y). */
    public static PublicKey es256PublicKey(byte[] x, byte[] y) {
        try {
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), p256()));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** The P-256 private key for a 32-byte big-endian scalar. */
    public static PrivateKey es256PrivateKey(byte[] d) {
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, d), p256()));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    // ---- signature suites: EdDSA (Ed25519) and ES256 (ECDSA P-256, IEEE-P1363 raw, low-S) ----

    private static final BigInteger P256_N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    private static final BigInteger P256_HALF_N = P256_N.shiftRight(1);

    private static boolean isCanonicalEs256(byte[] sig) {
        if (sig.length != 64) return false;
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
        return r.signum() > 0 && r.compareTo(P256_N) < 0 && s.signum() > 0 && s.compareTo(P256_HALF_N) <= 0;
    }

    private static byte[] signBytes(CoseAlg alg, PrivateKey key, byte[] msg) {
        try {
            if (alg == CoseAlg.EdDSA) {
                Signature s = Signature.getInstance("Ed25519");
                s.initSign(key);
                s.update(msg);
                return s.sign();
            }
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initSign(key);
            s.update(msg);
            byte[] sig = s.sign();
            // Normalise to low-S so a statement has exactly ONE valid signature form.
            BigInteger sv = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
            if (sv.compareTo(P256_HALF_N) > 0) {
                byte[] low = P256_N.subtract(sv).toByteArray();
                byte[] pad = new byte[32];
                System.arraycopy(low, Math.max(0, low.length - 32), pad, 32 - Math.min(32, low.length), Math.min(32, low.length));
                System.arraycopy(pad, 0, sig, 32, 32);
            }
            return sig;
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** May throw (a key of the wrong type); callers treat that as a failed verification. */
    private static boolean verifyBytes(CoseAlg alg, PublicKey key, byte[] msg, byte[] sig, boolean allowHighS) throws java.security.GeneralSecurityException {
        if (alg == CoseAlg.EdDSA) {
            byte[] enc = key.getEncoded();
            if (!"Ed25519".equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) throw new java.security.InvalidKeyException("not an Ed25519 key");
            if (enc == null || enc.length != 44 || !Arrays.equals(Arrays.copyOfRange(enc, 0, 12), ED_SPKI)) throw new java.security.InvalidKeyException("not an Ed25519 key");
            return EdStrict.verify(Arrays.copyOfRange(enc, 12, 44), msg, sig);
        }
        // ECDSA is malleable: reject high-S (and out-of-range scalars) before the curve check.
        if (!allowHighS && !isCanonicalEs256(sig)) return false;
        if (allowHighS && sig.length != 64) return false;
        Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
        s.initVerify(key);
        s.update(msg);
        try {
            return s.verify(sig);
        } catch (java.security.SignatureException e) {
            return false;
        }
    }

    /** The COSE_Sign1 Sig_structure to-be-signed bytes (RFC 9052 section 4.4), external_aad empty. */
    private static byte[] sigStructure(byte[] protectedBytes, byte[] payload) {
        return Cbor.encode(List.of("Signature1", protectedBytes, new byte[0], payload));
    }

    // ---- Signed Statements ----

    public static final class SignStatementOpts {
        public CoseAlg alg;
        /** The issuer's PRIVATE key. */
        public PrivateKey key;
        /** Issuer / feed identifier (CWT iss). */
        public String issuer;
        /** Optional subject (CWT sub). */
        public String subject;
        /** Payload content type (defaults to {@link #DEFAULT_CONTENT_TYPE}). */
        public String contentType;

        public SignStatementOpts(CoseAlg alg, PrivateKey key, String issuer) { this.alg = alg; this.key = key; this.issuer = issuer; }

        public SignStatementOpts subject(String s) { this.subject = s; return this; }

        public SignStatementOpts contentType(String c) { this.contentType = c; return this; }
    }

    /** Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1) over the strict-canonical serialization of the payload. */
    public static byte[] signStatement(Object payload, SignStatementOpts opts) {
        Map<Object, Object> prot = new LinkedHashMap<>();
        prot.put((long) HDR_ALG, opts.alg.label);
        prot.put((long) HDR_CONTENT_TYPE, opts.contentType != null ? opts.contentType : DEFAULT_CONTENT_TYPE);
        Map<Object, Object> claims = new LinkedHashMap<>();
        claims.put((long) CWT_ISS, opts.issuer);
        if (opts.subject != null) claims.put((long) CWT_SUB, opts.subject);
        prot.put((long) HDR_CWT_CLAIMS, claims);
        byte[] protectedBytes = Cbor.encode(prot);
        byte[] payloadBytes = Json.canonicalizeStrict(payload).getBytes(StandardCharsets.UTF_8);
        byte[] sig = signBytes(opts.alg, opts.key, sigStructure(protectedBytes, payloadBytes));
        return Cbor.encode(new Cbor.Tag(COSE_SIGN1_TAG, Arrays.asList(protectedBytes, new LinkedHashMap<Object, Object>(), payloadBytes, sig)));
    }

    /** A decoded, structurally validated COSE_Sign1. */
    public static final class CoseSign1 {
        public final byte[] protectedBytes;
        public final Map<Object, Object> protectedMap;
        public final Map<Object, Object> unprotected;
        /** The embedded payload, or null when detached. */
        public final byte[] payload;
        public final byte[] signature;

        CoseSign1(byte[] protectedBytes, Map<Object, Object> protectedMap, Map<Object, Object> unprotected, byte[] payload, byte[] signature) {
            this.protectedBytes = protectedBytes;
            this.protectedMap = protectedMap;
            this.unprotected = unprotected;
            this.payload = payload;
            this.signature = signature;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> decodeMap(Object v) {
        if (!(v instanceof Map)) throw err("cbor: expected a map");
        return (Map<Object, Object>) v;
    }

    /** Decode and structurally validate a COSE_Sign1 (tag 18). Throws on any deviation. */
    @SuppressWarnings("unchecked")
    public static CoseSign1 decodeCoseSign1(byte[] bytes) {
        Object top = Cbor.decode(bytes);
        if (!(top instanceof Cbor.Tag) || ((Cbor.Tag) top).tag != COSE_SIGN1_TAG) throw err("cose: not a COSE_Sign1 (tag 18)");
        Object arr = ((Cbor.Tag) top).value;
        if (!(arr instanceof List) || ((List<Object>) arr).size() != 4) throw err("cose: malformed COSE_Sign1 array");
        List<Object> a = (List<Object>) arr;
        Object protectedBytes = a.get(0), unprotected = a.get(1), payload = a.get(2), signature = a.get(3);
        if (!(protectedBytes instanceof byte[])) throw err("cose: protected must be a bstr");
        if (!(unprotected instanceof Map)) throw err("cose: unprotected must be a map");
        if (!(payload instanceof byte[]) && payload != null) throw err("cose: payload must be a bstr or nil");
        if (!(signature instanceof byte[])) throw err("cose: signature must be a bstr");
        byte[] pb = (byte[]) protectedBytes;
        Map<Object, Object> pm = pb.length == 0 ? new LinkedHashMap<>() : decodeMap(Cbor.decode(pb));
        return new CoseSign1(pb, pm, (Map<Object, Object>) unprotected, (byte[]) payload, (byte[]) signature);
    }

    private static CoseAlg algOf(Map<Object, Object> protectedMap) {
        Object label = protectedMap.get((long) HDR_ALG);
        if (label == null && !protectedMap.containsKey((long) HDR_ALG)) throw err("cose: missing alg header");
        CoseAlg alg = label instanceof Long ? algForLabel((Long) label) : null;
        if (alg == null) throw err("cose: unsupported alg");
        return alg;
    }

    /** Outcome of {@link #checkStatement}: success, or the specific reason verification failed. */
    public static final class StatementCheck {
        public final boolean ok;
        public final String reason;

        StatementCheck(boolean ok, String reason) { this.ok = ok; this.reason = reason; }

        /** The reference's shape: {ok: true} or {ok: false, reason}. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok);
            if (!ok) m.put("reason", reason);
            return m;
        }
    }

    private static StatementCheck fail(String reason) { return new StatementCheck(false, reason); }

    /**
     * Verify a Signed Statement and say WHY it failed: {@code malformed: <detail>}, {@code missing alg header}, {@code unsupported alg},
     * {@code detached payload}, {@code non-canonical signature (high-S)} (unless {@code allowHighS}) or {@code bad signature}.
     * Never throws. The COSE external_aad is always empty.
     */
    public static StatementCheck checkStatement(byte[] statement, PublicKey publicKey, boolean allowHighS) {
        CoseSign1 s;
        try {
            s = decodeCoseSign1(statement);
        } catch (RuntimeException e) {
            return fail("malformed: " + e.getMessage());
        }
        if (s.payload == null) return fail("detached payload");
        CoseAlg alg;
        try {
            alg = algOf(s.protectedMap);
        } catch (RuntimeException e) {
            return fail(e.getMessage() != null && e.getMessage().contains("missing") ? "missing alg header" : "unsupported alg");
        }
        try {
            byte[] msg = sigStructure(s.protectedBytes, s.payload);
            if (verifyBytes(alg, publicKey, msg, s.signature, allowHighS)) return new StatementCheck(true, null);
            if (alg == CoseAlg.ES256 && !isCanonicalEs256(s.signature) && verifyBytes(alg, publicKey, msg, s.signature, true)) {
                return fail("non-canonical signature (high-S)");
            }
            return fail("bad signature");
        } catch (Exception | StackOverflowError e) {
            return fail("bad signature");
        }
    }

    public static StatementCheck checkStatement(byte[] statement, PublicKey publicKey) { return checkStatement(statement, publicKey, false); }

    /** Verify a Signed Statement's COSE_Sign1 signature against the issuer public key. Never throws. */
    public static boolean verifyStatement(byte[] statement, PublicKey publicKey, boolean allowHighS) { return checkStatement(statement, publicKey, allowHighS).ok; }

    public static boolean verifyStatement(byte[] statement, PublicKey publicKey) { return verifyStatement(statement, publicKey, false); }

    /** The raw canonical payload bytes carried by a Signed Statement. Throws on a malformed statement. */
    public static byte[] statementPayload(byte[] statement) {
        CoseSign1 c = decodeCoseSign1(statement);
        if (c.payload == null) throw err("cose: statement payload is detached");
        return c.payload;
    }

    /** The b64u leaf a statement occupies in the transparency log. */
    public static String statementLeaf(byte[] statement) { return Keys.b64u(statement); }

    // ---- RFC 9162 inclusion proof codec: [tree_size, leaf_index, inclusion_path] ----

    private static long splitN(long n) {
        long k = 1;
        while (k * 2 < n) k *= 2;
        return k;
    }

    /** Sibling sides (leaf to root) for {@code index} in a tree of {@code size} leaves (RFC 6962 split). */
    public static List<String> siblingSides(long index, long size) {
        List<String> out = new ArrayList<>();
        long idx = index;
        long n = size;
        while (n > 1) {
            long k = splitN(n);
            if (idx < k) {
                out.add("R");
                n = k;
            } else {
                out.add("L");
                idx -= k;
                n -= k;
            }
        }
        java.util.Collections.reverse(out);
        return out;
    }

    /** A JSON number or plain number of the proof as the CBOR model value (Long when an exact safe integer, else Double). */
    static Object numberOf(Object o) {
        if (o instanceof Json.Num) {
            String raw = ((Json.Num) o).raw;
            try {
                java.math.BigDecimal d = new java.math.BigDecimal(raw);
                if (d.signum() == 0 && raw.startsWith("-")) return -0.0;
                java.math.BigInteger i = d.toBigIntegerExact();
                if (i.abs().compareTo(BigInteger.valueOf(Cbor.MAX_SAFE)) <= 0) return i.longValue();
            } catch (ArithmeticException | NumberFormatException e) {
                // not an exact integer
            }
            return Double.parseDouble(raw);
        }
        return o;
    }

    @SuppressWarnings("unchecked")
    private static List<byte[]> stepHashes(Object path) {
        if (!(path instanceof List)) throw err("path.map is not a function");
        List<byte[]> out = new ArrayList<>();
        for (Object step : (List<Object>) path) {
            if (!(step instanceof Map)) throw err("scitt: proof step hash is not a 32-byte b64u hash");
            byte[] h = Pca.decodeB64uStrict(((Map<String, Object>) step).get("hash"), 32);
            if (h == null) throw err("scitt: proof step hash is not a 32-byte b64u hash");
            out.add(h);
        }
        return out;
    }

    /** Encode a core-Merkle inclusion proof as an RFC 9162 inclusion proof (CBOR). */
    @SuppressWarnings("unchecked")
    public static byte[] encodeInclusionProof(Map<String, Object> proof) {
        List<Object> sibs = new ArrayList<>(stepHashes(proof.get("path")));
        if (!proof.containsKey("size") || !proof.containsKey("index")) throw err("cbor: unsupported value");
        return Cbor.encode(Arrays.asList(numberOf(proof.get("size")), numberOf(proof.get("index")), sibs));
    }

    /** A decoded inclusion proof: size, index and the raw sibling hashes (leaf to root). */
    private static final class Incl {
        long index;
        long size;
        List<byte[]> hashes = new ArrayList<>();
        List<String> sides;
    }

    @SuppressWarnings("unchecked")
    private static Incl decodeIncl(byte[] bytes) {
        Object v = Cbor.decode(bytes);
        if (!(v instanceof List) || ((List<Object>) v).size() != 3) throw err("scitt: malformed inclusion proof");
        List<Object> l = (List<Object>) v;
        Object size = l.get(0), index = l.get(1), sibs = l.get(2);
        if (!(size instanceof Long) || !(index instanceof Long)) throw err("scitt: proof size/index must be integers");
        long sz = (Long) size, ix = (Long) index;
        if (sz < 1 || ix < 0 || ix >= sz) throw err("scitt: proof size/index out of range");
        if (!(sibs instanceof List)) throw err("scitt: inclusion path must be an array");
        List<String> sides = siblingSides(ix, sz);
        List<Object> sl = (List<Object>) sibs;
        if (sl.size() != sides.size()) throw err("scitt: inclusion path length does not match (index,size)");
        Incl out = new Incl();
        out.index = ix;
        out.size = sz;
        out.sides = sides;
        for (Object h : sl) {
            if (!(h instanceof byte[]) || ((byte[]) h).length != 32) throw err("scitt: inclusion path entry must be a 32-byte bstr");
            out.hashes.add((byte[]) h);
        }
        return out;
    }

    /** Decode an RFC 9162 inclusion proof back into the core-Merkle proof map (sides re-derived). */
    public static Map<String, Object> decodeInclusionProof(byte[] bytes) { return inclMap(decodeIncl(bytes)); }

    private static Map<String, Object> inclMap(Incl in) {
        List<Object> path = new ArrayList<>();
        for (int i = 0; i < in.hashes.size(); i++) {
            Map<String, Object> step = new LinkedHashMap<>();
            step.put("side", in.sides.get(i));
            step.put("hash", Keys.b64u(in.hashes.get(i)));
            path.add(step);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", in.index);
        m.put("size", in.size);
        m.put("path", path);
        return m;
    }

    /** The core-Merkle proof map for leaf {@code index} of a {@code size}-leaf tree given its bottom-up sibling hashes. */
    public static Map<String, Object> inclusionProofMap(long index, long size, List<byte[]> hashes) {
        Incl in = new Incl();
        in.index = index;
        in.size = size;
        in.hashes = hashes;
        in.sides = siblingSides(index, size);
        return inclMap(in);
    }

    // ---- COSE Receipts (RFC 9942) ----

    public static final class ReceiptSignerOpts {
        public final CoseAlg alg;
        /** The Transparency Service PRIVATE key. */
        public final PrivateKey key;
        /** Optional TS issuer id (CWT iss in the receipt's protected header); may be null. */
        public final String issuer;

        public ReceiptSignerOpts(CoseAlg alg, PrivateKey key, String issuer) { this.alg = alg; this.key = key; this.issuer = issuer; }
    }

    /**
     * Build a signed COSE Receipt for {@code proof} against ledger root {@code root} (b64u, 32-byte SHA-256). The payload is detached;
     * the signature covers the root a verifier recomputes from the inclusion proof.
     */
    public static byte[] buildReceipt(String root, Map<String, Object> proof, ReceiptSignerOpts signer) {
        byte[] rootBytes = Pca.decodeB64uStrict(root, 32);
        if (rootBytes == null) throw err("scitt: tree root is not a 32-byte b64u hash");
        Map<Object, Object> prot = new LinkedHashMap<>();
        prot.put((long) HDR_ALG, signer.alg.label);
        prot.put((long) HDR_VDS, (long) VDS_RFC9162_SHA256);
        if (signer.issuer != null) {
            Map<Object, Object> claims = new LinkedHashMap<>();
            claims.put((long) CWT_ISS, signer.issuer);
            prot.put((long) HDR_CWT_CLAIMS, claims);
        }
        byte[] protectedBytes = Cbor.encode(prot);
        Map<Object, Object> proofs = new LinkedHashMap<>();
        proofs.put((long) PROOF_TYPE_INCLUSION, List.of(encodeInclusionProof(proof)));
        Map<Object, Object> unprotected = new LinkedHashMap<>();
        unprotected.put((long) HDR_VDS_PROOFS, proofs);
        byte[] sig = signBytes(signer.alg, signer.key, sigStructure(protectedBytes, rootBytes));
        return Cbor.encode(new Cbor.Tag(COSE_SIGN1_TAG, Arrays.asList(protectedBytes, unprotected, null, sig)));
    }

    public static final class VerifyReceiptOpts {
        /** The expected (pinned, out-of-band) tree root (b64u). */
        public String treeRoot;
        /** The Transparency Service PUBLIC key. */
        public PublicKey verificationKey;
        /** The issuer PUBLIC key of the Signed Statement. */
        public PublicKey statementKey;
        /** Accept ES256 signatures with a high S value. Default false. */
        public boolean allowHighS;
    }

    /**
     * Verify a COSE Receipt for a Signed Statement. FAIL-CLOSED (returns a boolean, never throws): an anchor is supplied; the receipt's TS
     * signature over the root verifies when {@code verificationKey} is given; the root equals {@code treeRoot} when given; the inclusion
     * proof binds the EXACT statement bytes to that root; the statement's own signature verifies when {@code statementKey} is given.
     */
    public static boolean verifyReceipt(byte[] receipt, byte[] statement, VerifyReceiptOpts opts) {
        try {
            if (opts.treeRoot == null && opts.verificationKey == null) return false;
            CoseSign1 cose = decodeCoseSign1(receipt);
            Object vds = cose.protectedMap.get((long) HDR_VDS);
            if (!(vds instanceof Long) || (Long) vds != VDS_RFC9162_SHA256) throw err("scitt: receipt is not RFC9162_SHA256");
            if (cose.payload != null && cose.payload.length != 32) throw err("scitt: receipt payload (root) must be 32 bytes");
            Object proofsRaw = cose.unprotected.get((long) HDR_VDS_PROOFS);
            if (!(proofsRaw instanceof Map)) throw err("scitt: missing verifiable-data-structure-proofs");
            Object inclusion = ((Map<?, ?>) proofsRaw).get((long) PROOF_TYPE_INCLUSION);
            if (!(inclusion instanceof List) || ((List<?>) inclusion).size() < 1) throw err("scitt: missing inclusion proof");
            Object first = ((List<?>) inclusion).get(0);
            if (!(first instanceof byte[])) throw err("scitt: inclusion proof must be a bstr");
            Incl proof = decodeIncl((byte[]) first);

            byte[] root = Rfc9162.rootFromInclusionPath(Rfc9162.leafHash(statement), proof.index, proof.size, proof.hashes);
            if (root == null) return false;
            if (cose.payload != null && !Arrays.equals(cose.payload, root)) return false;
            if (opts.verificationKey != null) {
                CoseAlg alg = algOf(cose.protectedMap);
                if (!verifyBytes(alg, opts.verificationKey, sigStructure(cose.protectedBytes, root), cose.signature, opts.allowHighS)) return false;
            }
            if (opts.treeRoot != null && !opts.treeRoot.equals(Keys.b64u(root))) return false;
            if (opts.statementKey != null && !verifyStatement(statement, opts.statementKey, opts.allowHighS)) return false;
            return true;
        } catch (Exception | StackOverflowError e) {
            return false;
        }
    }

    /** Result of a consistency proof request: both roots (b64u) and the RFC 9942 consistency-proof-content CBOR. */
    public static final class ConsistencyProofResult {
        public final long oldSize;
        public final long newSize;
        public final String oldRoot;
        public final String newRoot;
        public final byte[] proof;

        public ConsistencyProofResult(long oldSize, long newSize, String oldRoot, String newRoot, byte[] proof) {
            this.oldSize = oldSize;
            this.newSize = newSize;
            this.oldRoot = oldRoot;
            this.newRoot = newRoot;
            this.proof = proof;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("oldSize", oldSize);
            m.put("newSize", newSize);
            m.put("oldRoot", oldRoot);
            m.put("newRoot", newRoot);
            m.put("proof", proof);
            return m;
        }
    }

    /** Verify an RFC 9942 / RFC 9162 consistency proof between two pinned roots (b64u). FAIL-CLOSED boolean. */
    @SuppressWarnings("unchecked")
    public static boolean verifyConsistencyProof(byte[] proof, String oldRoot, String newRoot) {
        try {
            Object v = Cbor.decode(proof);
            if (!(v instanceof List) || ((List<Object>) v).size() != 3) return false;
            List<Object> l = (List<Object>) v;
            if (!(l.get(0) instanceof Long) || !(l.get(1) instanceof Long) || !(l.get(2) instanceof List)) return false;
            List<byte[]> path = new ArrayList<>();
            for (Object h : (List<Object>) l.get(2)) {
                if (!(h instanceof byte[])) return false;
                path.add((byte[]) h);
            }
            byte[] r1 = Pca.decodeB64uStrict(oldRoot, 32);
            byte[] r2 = Pca.decodeB64uStrict(newRoot, 32);
            if (r1 == null || r2 == null) return false;
            return Rfc9162.verifyConsistencyPath((Long) l.get(0), (Long) l.get(1), r1, r2, path);
        } catch (Exception | StackOverflowError e) {
            return false;
        }
    }
}
