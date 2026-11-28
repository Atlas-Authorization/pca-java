package net.atlasauth.pca.abe;

import net.atlasauth.pca.Json;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.IntFunction;
import java.util.function.Predicate;
import net.atlasauth.pca.pairing.Bls12;
import net.atlasauth.pca.pairing.Gt;
import supranational.blst.P1;
import supranational.blst.P2;

/**
 * FAME (Agrawal and Chase, ACM CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the type-3 pairing setting, the
 * group arithmetic only (the wire format, validation and AEAD are in {@link Abe}). G1/G2 work is blst through jblst,
 * GT work is blst through {@link Gt}. Same equations, hashing and span program as the TypeScript reference:
 *
 * <pre>
 *   Setup     MPK = (h^a1, h^a2, e(g,h)^(d1 a1 + d3), e(g,h)^(d2 a2 + d3)),  MSK = (a1, a2, b1, b2, g^d1, g^d2, g^d3)
 *   KeyGen    pow = (b1 r1, b2 r2, r1 + r2), K0 = h^pow,
 *             K_y,t = (H(y,0,t)^pow0 H(y,1,t)^pow1 H(y,2,t)^pow2 g^sigma_y)^(1/a_(t+1)), K_y,2 = g^-sigma_y,
 *             K'_t = (H0(0,0,t)^pow0 H0(0,1,t)^pow1 H0(0,2,t)^pow2 g^sigma')^(1/a_(t+1)) g^d_(t+1), K'_2 = g^-sigma' g^d3
 *   Encrypt   C0 = (h1^s1, h2^s2, h^(s1+s2)),
 *             C_i,l = H(rho(i),l,0)^s1 H(rho(i),l,1)^s2 prod_j (H0(j,l,0)^s1 H0(j,l,1)^s2)^M[i][j],  K = T1^s1 T2^s2
 *   Decrypt   K = prod_l e(keyProd_l, C0_l) / e(ctProd_l, K0_l) with the tree's Lagrange reconstruction weights
 * </pre>
 *
 * The span program is a Shamir sharing down the threshold tree (each t-of-n gate adds t-1 columns; child i gets its
 * parent's row plus i^k in the gate's k-th new column). rho must be injective: a policy naming one attribute twice is
 * refused by the caller.
 */
public final class Fame {
    private Fame() {}

    /** Domain-separation tag of the attribute / column random oracles (RFC 9380 SSWU_RO into G1). */
    public static final String ATTR_DST = "ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1";

    static final P1 G1 = P1.generator();
    static final P2 G2 = P2.generator();

    public static final class Mpk {
        public final P2 h1, h2;
        public final byte[] t1, t2;

        public Mpk(P2 h1, P2 h2, byte[] t1, byte[] t2) { this.h1 = h1; this.h2 = h2; this.t1 = t1; this.t2 = t2; }
    }

    public static final class Msk {
        public final BigInteger[] a, b;
        public final P1[] g;

        public Msk(BigInteger[] a, BigInteger[] b, P1[] g) { this.a = a; this.b = b; this.g = g; }
    }

    public static final class Key {
        public final P2[] k0;
        public final P1[] kp;
        public final Map<String, P1[]> attrs;

        public Key(P2[] k0, P1[] kp, Map<String, P1[]> attrs) { this.k0 = k0; this.kp = kp; this.attrs = attrs; }
    }

    public static final class Ciphertext {
        public final P2[] ct0;
        public final List<P1[]> rows;

        public Ciphertext(P2[] ct0, List<P1[]> rows) { this.ct0 = ct0; this.rows = rows; }
    }

    /** Setup output. */
    public static final class Master {
        public final Mpk mpk;
        public final Msk msk;

        Master(Mpk mpk, Msk msk) { this.mpk = mpk; this.msk = msk; }
    }

    /** Encrypt output: the ciphertext and the KEM key (a GT element). */
    public static final class Encapsulation {
        public final Ciphertext ct;
        public final byte[] k;

        Encapsulation(Ciphertext ct, byte[] k) { this.ct = ct; this.k = k; }
    }

    // ---- scalar multiplication with the reference's zero rule -------------------------------------------------------

    /** k*P for k non-zero mod r; a zero scalar throws (the reference refuses it). */
    static P1 mul(P1 p, BigInteger k) {
        if (Bls12.mod(k).signum() == 0) throw new ArithmeticException("scalar is zero");
        return Bls12.mul(p, k);
    }

    static P2 mul(P2 p, BigInteger k) {
        if (Bls12.mod(k).signum() == 0) throw new ArithmeticException("scalar is zero");
        return Bls12.mul(p, k);
    }

    /** k*P, the identity when k is zero mod r. */
    static P1 mulZ(P1 p, BigInteger k) { return Bls12.mul(p, k); }

    // ---- random oracles ---------------------------------------------------------------------------------------------

    static P1 hashToG1(byte[] msg) { return new P1().hash_to(msg, ATTR_DST); }

    private static byte[] u32(int n) { return new byte[] {(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n}; }

    /** H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t. */
    public static P1 hAttr(String attr, int l, int t) {
        byte[] a = Json.utf8(attr);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(1);
        o.writeBytes(u32(a.length));
        o.writeBytes(a);
        o.write(l);
        o.write(t);
        return hashToG1(o.toByteArray());
    }

    /** H0(j, l, t): the column-indexed oracle (kind byte 2). */
    public static P1 hCol(int j, int l, int t) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(2);
        o.writeBytes(u32(j));
        o.write(l);
        o.write(t);
        return hashToG1(o.toByteArray());
    }

    // ---- setup / keygen ---------------------------------------------------------------------------------------------

    public static Master setup(BigInteger[] a, BigInteger[] b, BigInteger[] d) {
        byte[] egh = Gt.pairing(G1, G2);
        Mpk mpk = new Mpk(mul(G2, a[0]), mul(G2, a[1]),
            Gt.pow(egh, Bls12.add(Bls12.mul(d[0], a[0]), d[2])), Gt.pow(egh, Bls12.add(Bls12.mul(d[1], a[1]), d[2])));
        return new Master(mpk, new Msk(a, b, new P1[] {mul(G1, d[0]), mul(G1, d[1]), mul(G1, d[2])}));
    }

    private static P1 keyTerm(IntFunction<P1> oracle, BigInteger[] pow, BigInteger sigma, BigInteger aInv) {
        P1 sum = mulZ(oracle.apply(0), pow[0]).add(mulZ(oracle.apply(1), pow[1])).add(mulZ(oracle.apply(2), pow[2])).add(mul(G1, sigma));
        return mul(sum, aInv);
    }

    public static Key keygen(Msk msk, List<String> attrs, BigInteger[] r, List<BigInteger> sigmas, BigInteger sigmaPrime) {
        BigInteger[] pow = {Bls12.mul(msk.b[0], r[0]), Bls12.mul(msk.b[1], r[1]), Bls12.add(r[0], r[1])};
        BigInteger[] aInv = {Bls12.inv(msk.a[0]), Bls12.inv(msk.a[1])};
        P2[] k0 = {mul(G2, pow[0]), mul(G2, pow[1]), mul(G2, pow[2])};
        Map<String, P1[]> out = new LinkedHashMap<>();
        for (int i = 0; i < attrs.size(); i++) {
            String y = attrs.get(i);
            if (i >= sigmas.size()) throw new IllegalArgumentException("fameKeygen: one sigma per attribute is required");
            BigInteger sg = sigmas.get(i);
            out.put(y, new P1[] {
                keyTerm(l -> hAttr(y, l, 0), pow, sg, aInv[0]),
                keyTerm(l -> hAttr(y, l, 1), pow, sg, aInv[1]),
                mul(G1, Bls12.sub(BigInteger.ZERO, sg))});
        }
        P1[] kp = {
            keyTerm(l -> hCol(0, l, 0), pow, sigmaPrime, aInv[0]).add(msk.g[0]),
            keyTerm(l -> hCol(0, l, 1), pow, sigmaPrime, aInv[1]).add(msk.g[1]),
            mul(G1, Bls12.sub(BigInteger.ZERO, sigmaPrime)).add(msk.g[2])};
        return new Key(k0, kp, out);
    }

    // ---- span program -----------------------------------------------------------------------------------------------

    static final class Row {
        final String attr;
        final Map<Integer, BigInteger> vec;

        Row(String attr, Map<Integer, BigInteger> vec) { this.attr = attr; this.vec = vec; }
    }

    /** Leaves in depth-first order, each with its sparse span-program row (column 0 is the secret column, always 1). */
    static List<Row> buildRows(Map<String, Object> tree) {
        List<Row> rows = new ArrayList<>();
        int[] ncols = {1};
        Map<Integer, BigInteger> start = new LinkedHashMap<>();
        start.put(0, BigInteger.ONE);
        walk(tree, start, rows, ncols);
        return rows;
    }

    private static void walk(Map<String, Object> node, Map<Integer, BigInteger> vec, List<Row> rows, int[] ncols) {
        if (AbePolicy.isLeaf(node)) {
            rows.add(new Row((String) node.get("attr"), vec));
            return;
        }
        int t = AbePolicy.t(node);
        int base = ncols[0];
        ncols[0] += t - 1;
        List<Map<String, Object>> of = AbePolicy.of(node);
        for (int idx = 0; idx < of.size(); idx++) {
            Map<Integer, BigInteger> cv = new LinkedHashMap<>(vec);
            BigInteger x = BigInteger.valueOf(idx + 1), pw = BigInteger.ONE;
            for (int k = 1; k < t; k++) {
                pw = Bls12.mul(pw, x);
                cv.put(base + k - 1, pw);
            }
            walk(of.get(idx), cv, rows, ncols);
        }
    }

    static int leafCount(Map<String, Object> tree) {
        if (AbePolicy.isLeaf(tree)) return 1;
        int n = 0;
        for (Map<String, Object> c : AbePolicy.of(tree)) n += leafCount(c);
        return n;
    }

    /** First attribute named by two leaves, or null (FAME needs an injective row labelling). */
    static String firstRepeatedAttribute(Map<String, Object> tree) {
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (String a : AbePolicy.leaves(tree)) if (!seen.add(a)) return a;
        return null;
    }

    // ---- encrypt ----------------------------------------------------------------------------------------------------

    public static Encapsulation encrypt(Mpk mpk, Map<String, Object> tree, BigInteger[] s) {
        List<Row> rows = buildRows(tree);
        Map<String, P1> colMemo = new HashMap<>();
        List<P1[]> out = new ArrayList<>();
        for (Row row : rows) {
            P1[] tri = new P1[3];
            for (int l = 0; l < 3; l++) {
                P1 acc = mul(hAttr(row.attr, l, 0), s[0]).add(mul(hAttr(row.attr, l, 1), s[1]));
                for (Map.Entry<Integer, BigInteger> e : row.vec.entrySet()) {
                    int j = e.getKey(), ll = l;
                    P1 col = colMemo.computeIfAbsent(j + ":" + l, key -> mul(hCol(j, ll, 0), s[0]).add(mul(hCol(j, ll, 1), s[1])));
                    acc = acc.add(mulZ(col, e.getValue()));
                }
                tri[l] = acc;
            }
            out.add(tri);
        }
        Ciphertext ct = new Ciphertext(new P2[] {mul(mpk.h1, s[0]), mul(mpk.h2, s[1]), mul(G2, Bls12.add(s[0], s[1]))}, out);
        return new Encapsulation(ct, Gt.mul(Gt.pow(mpk.t1, s[0]), Gt.pow(mpk.t2, s[1])));
    }

    // ---- decrypt ----------------------------------------------------------------------------------------------------

    /** A decryption plan: a leaf row, or a gate with the chosen children and their evaluation points. */
    private static final class Plan {
        final int row;
        final List<BigInteger> xs;
        final List<Plan> subs;

        Plan(int row) { this.row = row; this.xs = null; this.subs = null; }

        Plan(List<BigInteger> xs, List<Plan> subs) { this.row = -1; this.xs = xs; this.subs = subs; }
    }

    /** Bottom-up, the first t satisfiable children of every gate; null when the subtree is not satisfied. */
    private static Plan plan(Map<String, Object> node, Predicate<String> has, int offset) {
        if (AbePolicy.isLeaf(node)) return has.test((String) node.get("attr")) ? new Plan(offset) : null;
        int t = AbePolicy.t(node);
        List<BigInteger> xs = new ArrayList<>();
        List<Plan> subs = new ArrayList<>();
        int off = offset;
        List<Map<String, Object>> of = AbePolicy.of(node);
        for (int i = 0; i < of.size(); i++) {
            Plan sub = plan(of.get(i), has, off);
            if (sub != null) {
                xs.add(BigInteger.valueOf(i + 1));
                subs.add(sub);
            }
            if (subs.size() >= t) break;
            off += leafCount(of.get(i));
        }
        return subs.size() < t ? null : new Plan(xs, subs);
    }

    private static boolean weights(Plan p, BigInteger w, Map<Integer, BigInteger> out) {
        if (p.subs == null) {
            out.put(p.row, w);
            return true;
        }
        List<BigInteger> lambda = lagrangeAtZero(p.xs);
        if (lambda == null) return false;
        for (int i = 0; i < p.subs.size(); i++) if (!weights(p.subs.get(i), Bls12.mul(w, lambda.get(i)), out)) return false;
        return true;
    }

    /** Lagrange coefficients L_i(0) over Z_r; null on an empty set, a zero point, or coinciding points. */
    static List<BigInteger> lagrangeAtZero(List<BigInteger> xs) {
        if (xs.isEmpty()) return null;
        java.util.Set<BigInteger> seen = new java.util.HashSet<>();
        for (BigInteger x : xs) {
            BigInteger xr = Bls12.mod(x);
            if (xr.signum() == 0 || !seen.add(xr)) return null;
        }
        List<BigInteger> out = new ArrayList<>();
        for (int i = 0; i < xs.size(); i++) {
            BigInteger num = BigInteger.ONE, den = BigInteger.ONE;
            for (int j = 0; j < xs.size(); j++) {
                if (j == i) continue;
                num = Bls12.mul(num, xs.get(j));
                den = Bls12.mul(den, Bls12.sub(xs.get(j), xs.get(i)));
            }
            out.add(Bls12.mul(num, Bls12.inv(den)));
        }
        return out;
    }

    /** Row index -> reconstruction weight over the rows the key can use; null when the attribute set does not satisfy the tree. */
    static Map<Integer, BigInteger> reconstructionWeights(Map<String, Object> tree, Predicate<String> has) {
        Plan p = plan(tree, has, 0);
        if (p == null) return null;
        Map<Integer, BigInteger> out = new LinkedHashMap<>();
        return weights(p, BigInteger.ONE, out) ? out : null;
    }

    /** The KEM key, or null when the key does not satisfy the tree (or a pairing input is the identity). */
    public static byte[] decrypt(Key key, Map<String, Object> tree, Ciphertext ct) {
        List<String> rows = AbePolicy.leaves(tree);
        if (rows.size() != ct.rows.size()) return null;
        Map<Integer, BigInteger> w = reconstructionWeights(tree, key.attrs::containsKey);
        if (w == null) return null;
        List<P1> g1 = new ArrayList<>();
        List<P2> g2 = new ArrayList<>();
        for (int l = 0; l < 3; l++) {
            P1 ctProd = new P1();
            P1 keyProd = key.kp[l].dup();
            for (Map.Entry<Integer, BigInteger> e : w.entrySet()) {
                P1[] comp = key.attrs.get(rows.get(e.getKey()));
                P1[] cRow = ct.rows.get(e.getKey());
                if (comp == null || cRow == null) return null;
                ctProd = ctProd.add(mulZ(cRow[l], e.getValue()));
                keyProd = keyProd.add(mulZ(comp[l], e.getValue()));
            }
            g1.add(keyProd);
            g2.add(ct.ct0[l]);
            g1.add(ctProd.dup().neg());
            g2.add(key.k0[l]);
        }
        try {
            return Gt.pairingProduct(g1, g2);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
